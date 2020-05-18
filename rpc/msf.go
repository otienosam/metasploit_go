package rpc

import (
	"bytes"
	"fmt"
	"net/http"

	"gopkg.in/vmihailenco/msgpack.v2"
)

type Metasploit struct {// configuration struct
	host  string
	user  string
	pass  string
	token string
}

func New(host, user, pass string) (*Metasploit, error) {
	// rpc Method
  // implicitly available data from the struct type
	msf := &Metasploit{
		host: host,
		user: user,
		pass: pass,
	}

	if err := msf.Login(); err != nil {// explicit call to the login()
		return nil, err
	}

	return msf, nil
}

func (msf *Metasploit) send(req interface{}, res interface{}) error {
	buf := new(bytes.Buffer)
	msgpack.NewEncoder(buf).Encode(req)// populates buf with msgpack encoded
  // representation of the struct
	dest := fmt.Sprintf("http://%s/api", msf.host)//msf -Metasploit receiver
	r, err := http.Post(dest, "binary/message-pack", buf)// body set to serialzed
	// data
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if err := msgpack.NewDecoder(r.Body).Decode(&res); err != nil {
		return err
	}

	return nil
}

type loginReq struct {
	_msgpack struct{} `msgpack:",asArray"`
	Method   string
	Username string
	Password string
}

type loginRes struct {//response dynamically serialzed populating only the
  // present fields
	Result       string `msgpack:"result"`
	Token        string `msgpack:"token"`
	Error        bool   `msgpack:"error"`
	ErrorClass   string `msgpack:"error_class"`
	ErrorMessage string `msgpack:"error_message"`
}

type logoutReq struct {
	_msgpack    struct{} `msgpack:",asArray"`
	Method      string
	Token       string
	LogoutToken string
}

type logoutRes struct {
	Result string `msgpack:"result"`
}

type sessionListReq struct {
	_msgpack struct{} `msgpack:",asArray"`// descriptor asArray treats the
  // data as positional  arrays
	Method   string
	Token    string
}

type SessionListRes struct {
	ID          uint32 `msgpack:",omitempty"`//make the data optional to use
  // the key value type so that it doesnt impact decoding/encoding.
  //This flattens the data so that use of nested maps isnt mandatory
	Type        string `msgpack:"type"`
	TunnelLocal string `msgpack:"tunnel_local"`
	TunnelPeer  string `msgpack:"tunnel_peer"`
	ViaExploit  string `msgpack:"via_exploit"`
	ViaPayload  string `msgpack:"via_payload"`
	Description string `msgpack:"desc"`
	Info        string `msgpack:"info"`
	Workspace   string `msgpack:"workspace"`
	SessionHost string `msgpack:"session_host"`
	SessionPort int    `msgpack:"session_port"`
	Username    string `msgpack:"username"`
	UUID        string `msgpack:"uuid"`
	ExploitUUID string `msgpack:"exploit_uuid"`
}

func (msf *Metasploit) Login() error {
	ctx := &loginReq{
		Method:   "auth.login",
		Username: msf.user,
		Password: msf.pass,
	}
	var res loginRes
	if err := msf.send(ctx, &res); err != nil {
		return err
	}
	msf.token = res.Token
	return nil
}
func (msf *Metasploit) Logout() error {
	ctx := &logoutReq{
		Method:      "auth.logout",
		Token:       msf.token,
		LogoutToken: msf.token,
	}
	var res logoutRes
	if err := msf.send(ctx, &res); err != nil {
		return err
	}
	msf.token = ""
	return nil
}
func (msf *Metasploit) SessionList() (map[uint32]SessionListRes, error) {
	req := &sessionListReq{Method: "session.list", Token: msf.token}
	res := make(map[uint32]SessionListRes)
	if err := msf.send(req, &res); err != nil {
		return nil, err
	}

	for id, session := range res {
		session.ID = id
		res[id] = session
	}
	return res, nil
}
