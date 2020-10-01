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
  Fields = [ """\w+\s+\d+ \d+:\d+:\d+ ({host}[\w.\-]+)""",
             """({time}\d+/\d+/\d+ \d+:\d+:\d+)""",
             """\[({user}[\w.'\-]+)\]:({contivity_session_id}\d+) logged out""" ]
}
```