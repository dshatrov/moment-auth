#include <libmary/module_init.h>
#include <moment/libmoment.h>


using namespace M;
using namespace Moment;


namespace {
class MomentAuthModule : public Object
{
private:
    class AuthSession : public MomentServer::AuthSession
    {
    public:
        Mutex mutex;

        mt_mutex (mutex) Ref<String> auth_key;
        mt_mutex (mutex) Uint64 num_active_requests;
        mt_mutex (mutex) Uint64 num_complete_requests;
        mt_mutex (mutex) bool disconnected;
        mt_mutex (mutex) bool disconnected_sent;
    };

    mt_const Ref<MomentServer> moment;

    mt_const Ref<String> this_host;

    mt_const Ref<String> watch_req;
    mt_const bool watch_req_enabled;
    mt_const bool watch_req_has_params;

    mt_const Ref<String> stream_req;
    mt_const bool stream_req_enabled;
    mt_const bool stream_req_has_params;

    mt_const Ref<String> disconnected_req;
    mt_const bool disconnected_req_enabled;
    mt_const bool disconnected_req_has_params;

    HttpClient http_client;

    void sendDisconnected (ConstMemory auth_key);

    void finishAuthSessionRequest (AuthSession * mt_nonnull auth_session,
                                   bool         successful_request);

  mt_iface (MomentServer::AuthBackend)

    static MomentServer::AuthBackend const auth_backend;

    static Ref<MomentServer::AuthSession> newAuthSession (void *_self);

    struct CheckAuthorization_Data : public Referenced
    {
        WeakRef<MomentAuthModule> weak_moment_auth;
        Ref<AuthSession> auth_session;
        Cb<MomentServer::CheckAuthorizationCallback> cb;
    };

    static bool checkAuthorization (MomentServer::AuthSession *_auth_session,
                                    MomentServer::AuthAction   auth_action,
                                    ConstMemory                stream_name,
                                    ConstMemory                auth_key,
                                    IpAddress                  client_addr,
                                    CbDesc<MomentServer::CheckAuthorizationCallback> const &cb,
                                    bool                      * mt_nonnull ret_authorized,
                                    void                      *_self);

    static void authSessionDisconnected (MomentServer::AuthSession *_auth_session,
                                         ConstMemory                auth_key,
                                         void                      *_self);

  mt_iface_end

  mt_iface (HttpClient::HttpResponseHandler)

    static HttpClient::HttpResponseHandler const auth_response_handler;

    static Result authHttpResponse (HttpRequest   *resp,
                                    Memory const  &msg_body,
                                    void         ** mt_nonnull /* ret_msg_data */,
                                    void          *_data);

  mt_iface_end

public:
    mt_const void init (MomentServer * mt_nonnull moment,
                        IpAddress     auth_addr,
                        ConstMemory   auth_host,
                        ConstMemory   this_host,
                        ConstMemory   watch_req,
                        bool          watch_req_enabled,
                        ConstMemory   stream_req,
                        bool          stream_req_enabled,
                        ConstMemory   disconnected_req,
                        bool          disconnected_req_enabled);

    MomentAuthModule ();
};
}

static MomentAuthModule *moment_auth;


static Result disconnectedHttpResponse (HttpRequest   * const resp,
                                        Memory const  & /* msg_body */,
                                        void         ** const mt_nonnull /* ret_msg_data */,
                                        void          * const /* cb_data */)
{
    if (!resp)
        logE_ (_func, "request error");

    return Result::Success;
}

static HttpClient::HttpResponseHandler const disconnected_response_handler = {
    disconnectedHttpResponse,
    NULL /* httpResponseBody */
};

void
MomentAuthModule::sendDisconnected (ConstMemory const auth_key)
{
    if (!disconnected_req_enabled)
        return;

    Ref<String> const req_str =
            makeString ("/", disconnected_req->mem(), (disconnected_req_has_params ? "&" : "?"),
                        "host=", this_host->mem(),
                        "&auth=", auth_key);

    if (!http_client.httpGet (req_str->mem(),
                              CbDesc<HttpClient::HttpResponseHandler> (&disconnected_response_handler,
                                                                       NULL,
                                                                       NULL),
                              true  /* preassembly */,
                              false /* parse_body_params */))
    {
        logE_ (_func, "httpGet() failed");
    }
}

void
MomentAuthModule::finishAuthSessionRequest (AuthSession * const mt_nonnull auth_session,
                                            bool          const successful_request)
{
    bool send_disconnected = false;
    Ref<String> auth_key;
    {
        auth_session->mutex.lock ();

        if (successful_request)
            ++auth_session->num_complete_requests;

        assert (auth_session->num_active_requests > 0);
        --auth_session->num_active_requests;
        if (auth_session->num_active_requests == 0
            && auth_session->disconnected
            && !auth_session->disconnected_sent
            && auth_session->num_complete_requests > 0)
        {
            auth_session->disconnected_sent = true;
            send_disconnected = true;
            auth_key = auth_session->auth_key;
        }
        auth_session->mutex.unlock ();
    }

    if (send_disconnected)
        sendDisconnected (auth_key->mem());
}

MomentServer::AuthBackend const MomentAuthModule::auth_backend = {
    newAuthSession,
    checkAuthorization,
    authSessionDisconnected
};

Ref<MomentServer::AuthSession>
MomentAuthModule::newAuthSession (void * const /* _self */)
{
//    MomentAuthModule * const self = static_cast <MomentAuthModule*> (_self);

    AuthSession * const auth_session = new AuthSession;
    auth_session->num_active_requests = 0;
    auth_session->num_complete_requests = 0;
    auth_session->disconnected = false;
    auth_session->disconnected_sent = false;
    return grab (static_cast <MomentServer::AuthSession*> (auth_session));
}

HttpClient::HttpResponseHandler const MomentAuthModule::auth_response_handler = {
    authHttpResponse,
    NULL /* httpResponseBody */
};

Result
MomentAuthModule::authHttpResponse (HttpRequest   * const resp,
                                    Memory const  &msg_body,
                                    void         ** const mt_nonnull /* ret_msg_data */,
                                    void          * const _data)
{
    CheckAuthorization_Data * const data = static_cast <CheckAuthorization_Data*> (_data);

    // Not that 'self' may be NULL.
    Ref<MomentAuthModule> const self = data->weak_moment_auth.getRef ();

    if (!resp) {
        if (self && data->auth_session)
            self->finishAuthSessionRequest (data->auth_session, false /* successful_request */);

        logE_ (_func, "request error");
        data->cb.call_ (false /* authorized */);
        return Result::Success;
    }

//    logD_ (_func, "msg_body.len(): ", msg_body.len());
//    hexdump (logs, msg_body);

    Size body_len = msg_body.len();
    while (body_len > 0) {
        if (msg_body.mem() [body_len - 1] != '\r' &&
            msg_body.mem() [body_len - 1] != '\n')
        {
            break;
        }

        --body_len;
    }

    bool const authorized = equal ("OK", msg_body.region (0, body_len));
    if (authorized)
        data->cb.call_ (true /* authorized */);
    else
        data->cb.call_ (false /* authorized */);

    if (self && data->auth_session)
        self->finishAuthSessionRequest (data->auth_session, authorized /* successful_request */);

    return Result::Success;
}

bool
MomentAuthModule::checkAuthorization (MomentServer::AuthSession * const _auth_session,
                                      MomentServer::AuthAction    const auth_action,
                                      ConstMemory                 const stream_name,
                                      ConstMemory                 const auth_key,
                                      IpAddress                   const client_addr,
                                      CbDesc<MomentServer::CheckAuthorizationCallback> const &cb,
                                      bool                      * const mt_nonnull ret_authorized,
                                      void                      * const _self)
{
    AuthSession * const auth_session = static_cast <AuthSession*> (_auth_session);
    MomentAuthModule * const self = static_cast <MomentAuthModule*> (_self);

    *ret_authorized = false;

    logD_ (_func, "stream_name: ", stream_name, ", "
           "auth_key: ", auth_key, ", "
           "client_addr: ", client_addr);

    if (auth_session) {
        auth_session->mutex.lock ();

        if (!auth_session->auth_key) {
            auth_session->auth_key = grab (new String (auth_key));
        } else {
            if (!equal (auth_session->auth_key->mem(), auth_key))
                logF_ (_func, "WARNING: Different auth keys used for the same AuthSession");
        }

        if (auth_session->disconnected) {
            auth_session->mutex.unlock ();
            logF_ (_func, "WARNING: Auth check for a disconnected auth session");
            *ret_authorized = false;
            return true;
        }

        ++auth_session->num_active_requests;
        auth_session->mutex.unlock ();
    }

    Ref<CheckAuthorization_Data> const data = grab (new CheckAuthorization_Data);
    data->weak_moment_auth = self;
    data->auth_session = auth_session;
    data->cb = cb;

    Ref<String> req_str;
    switch (auth_action) {
        case MomentServer::AuthAction_Watch: {
            if (self->watch_req_enabled)
                req_str = makeString ("/", self->watch_req->mem(), (self->watch_req_has_params ? "&" : "?"));
        } break;
        case MomentServer::AuthAction_Stream: {
            if (self->stream_req_enabled)
                req_str = makeString ("/", self->stream_req->mem(), (self->stream_req_has_params ? "&" : "?"));
        } break;
        default:
            unreachable ();
    }
    if (!req_str) {
        *ret_authorized = true;
        return true;
    }

    req_str = makeString (req_str->mem(),
                          "host=", self->this_host->mem(),
                          "&client=", IpAddress_NoPort (client_addr),
                          "&stream=", stream_name,
                          "&auth=", auth_key);

    if (!self->http_client.httpGet (req_str->mem(),
                                    CbDesc<HttpClient::HttpResponseHandler> (&auth_response_handler,
                                                                             data,
                                                                             NULL,
                                                                             data),
                                    true /* preassembly */,
                                    true /* parse_body_params */))
    {
        if (auth_session) {
            auth_session->mutex.lock ();
            --auth_session->num_active_requests;
            auth_session->mutex.unlock ();
        }

        logE_ (_func, "httpGet() failed");
        *ret_authorized = false;
        return true;
    }

    return false;
}

void
MomentAuthModule::authSessionDisconnected (MomentServer::AuthSession * const _auth_session,
                                           ConstMemory                 const auth_key,
                                           void                      * const _self)
{
    AuthSession * const auth_session = static_cast <AuthSession*> (_auth_session);
    MomentAuthModule * const self = static_cast <MomentAuthModule*> (_self);

    if (auth_session) {
        auth_session->mutex.lock ();

        if (auth_session->auth_key
            && !equal (auth_session->auth_key->mem(), auth_key))
        {
            logF_ (_func, "WARNING: Different auth keys used for the same AuthSession");
        }

        if (auth_session->disconnected) {
            auth_session->mutex.unlock ();
            return;
        }

        auth_session->disconnected = true;
        if (auth_session->num_active_requests > 0) {
            auth_session->mutex.unlock ();
            return;
        }

        if (auth_session->num_complete_requests == 0) {
            auth_session->mutex.unlock ();
            return;
        }

        auth_session->disconnected_sent = true;

        auth_session->mutex.unlock ();
    }

    self->sendDisconnected (auth_key);
}

mt_const void
MomentAuthModule::init (MomentServer * const mt_nonnull moment,
                        IpAddress      const auth_addr,
                        ConstMemory    const auth_host,
                        ConstMemory    const this_host,
                        ConstMemory    const watch_req,
                        bool           const watch_req_enabled,
                        ConstMemory    const stream_req,
                        bool           const stream_req_enabled,
                        ConstMemory    const disconnected_req,
                        bool           const disconnected_req_enabled)
{
    this->moment = moment;
    this->this_host = grab (new String (this_host));

    this->watch_req = grab (new String (watch_req));
    this->watch_req_enabled = watch_req_enabled;
    watch_req_has_params = (bool) strchr (this->watch_req->cstr(), '?');

    this->stream_req = grab (new String (stream_req));
    this->stream_req_enabled = stream_req_enabled;
    stream_req_has_params = (bool) strchr (this->stream_req->cstr(), '?');

    this->disconnected_req = grab (new String (disconnected_req));
    this->disconnected_req_enabled = disconnected_req_enabled;
    disconnected_req_has_params = (bool) strchr (this->disconnected_req->cstr(), '?');

    {
        http_client.init (moment->getServerApp()->getServerContext(),
                          moment->getPagePool(),
                          auth_addr,
                          auth_host,
                          false /* keepalive */,
                          1 << 20 /* 1 Mb */ /* preassembly_limit */);
    }


    moment->setAuthBackend (CbDesc<MomentServer::AuthBackend> (&auth_backend, this, this));
}

MomentAuthModule::MomentAuthModule ()
    : http_client (this)
{
}

static void momentAuthInit ()
{
    logD_ (_func_);

    Ref<MomentServer> const moment = MomentServer::getInstance();
    MConfig::Config * const config = moment->getConfig ();

    {
	ConstMemory const opt_name = "mod_auth/enable";
	MConfig::BooleanValue const enable = config->getBoolean (opt_name);
	if (enable == MConfig::Boolean_Invalid) {
	    logE_ (_func, "Invalid value for ", opt_name, ": ", config->getString (opt_name));
	    return;
	}

	if (enable != MConfig::Boolean_True) {
	    logI_ (_func, "Auth module is not enabled. "
		   "Set \"", opt_name, "\" option to \"y\" to enable.");
	    return;
	}
    }

    ConstMemory auth_host;
    IpAddress auth_addr;
    {
        ConstMemory const opt_name = "mod_auth/auth_host";
        auth_host = config->getString (opt_name);
        if (auth_host.isNull()) {
            logI_ (_func, opt_name,  " is empty, disabling mod_auth");
            return;
        }

        logD_ (_func, opt_name, ": ", auth_host);

        if (!setIpAddress_default (auth_host,
                                   ConstMemory() /* default_host */,
                                   80            /* default_port */,
                                   false         /* allow_any_host */,
                                   &auth_addr))
        {
            logE_ (_func, "bad ", opt_name, ": ", auth_host, ", disabling mod_auth");
            return;
        }
    }

    ConstMemory this_host;
    {
        ConstMemory const opt_name = "mod_auth/this_host";
        this_host = config->getString (opt_name);
        logD_ (_func, opt_name, ": ", this_host);
    }

    ConstMemory watch_req;
    bool watch_req_enabled = false;
    {
        ConstMemory const opt_name = "mod_auth/watch_req";
        watch_req = config->getString (opt_name, &watch_req_enabled);
        logD_ (_func, opt_name, ": ", watch_req);

        if (!watch_req_enabled)
            logD_ (_func, "watch auth check is not enabled");
    }

    ConstMemory stream_req;
    bool stream_req_enabled = false;
    {
        ConstMemory const opt_name = "mod_auth/stream_req";
        stream_req = config->getString (opt_name, &stream_req_enabled);
        logD_ (_func, opt_name, ": ", stream_req);

        if (!stream_req_enabled)
            logD_ (_func, "stream auth check is not enabled");
    }

    ConstMemory disconnected_req;
    bool disconnected_req_enabled = false;
    {
        ConstMemory const opt_name = "mod_auth/disconnected_req";
        disconnected_req = config->getString (opt_name, &disconnected_req_enabled);
        logD_ (_func, opt_name, ": ", disconnected_req);

        if (!disconnected_req_enabled)
            logD_ (_func, "disconnect auth notification is not enabled");
    }

    moment_auth = new MomentAuthModule;
    moment_auth->init (moment,
                       auth_addr,
                       auth_host,
                       this_host,
                       watch_req,
                       watch_req_enabled,
                       stream_req,
                       stream_req_enabled,
                       disconnected_req,
                       disconnected_req_enabled);
}

static void momentAuthUnload ()
{
    logD_ (_func_);

    moment_auth->unref ();
}


namespace M {

void libMary_moduleInit ()
{
    momentAuthInit ();
}

void libMary_moduleUnload ()
{
    momentAuthUnload ();
}

}

