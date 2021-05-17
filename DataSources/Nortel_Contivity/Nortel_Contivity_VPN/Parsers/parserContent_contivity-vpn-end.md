#### Parser Content
```Java
{
Name = contivity-vpn-end
  Vendor = Nortel Contivity
  Product = Nortel Contivity VPN
  Lms = Splunk
  DataType = "vpn-end"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ "Security", "logged out", "tEvtLgMgr" ]
  Fields = [ """\w+\s{1,100}\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} ({host}[\w.\-]{1,2000})""",
             """({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
             """\[({user}[\w.'\-]{1,2000})\]:({contivity_session_id}\d{1,100}) logged out""" ]
}
```