#### Parser Content
```Java
{
Name = contivity-vpn-set-ip
  Vendor = Nortel Contivity
  Product = Nortel Contivity VPN
  Lms = Splunk
  DataType = "vpn-set-ip"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ "tEvtLgMgr", "assigned IP address" ]
  Fields = [ """\w+\s{1,100}\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} ({host}[\w.\-]{1,2000})""",
             """({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
             """\[({user}[\w.'\-]{1,2000})\]:({contivity_session_id}\d{1,100}) assigned IP address ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""" ]
}
}
```