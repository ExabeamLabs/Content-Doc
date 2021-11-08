#### Parser Content
```Java
{
Name = contivity-vpn-start
  Vendor = Nortel Contivity
  Product = Nortel Contivity VPN
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ "tEvtLgMgr", "physical addresses:" ]
  Fields = [ """\w+\s{1,100}\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} ({host}[\w.\-]{1,2000})""",
             """({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
             """\[({user}[\w.'\-]{1,2000})\]:({contivity_session_id}\d{1,100})""",
             """physical addresses: remote ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) local ({dest_host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""" ]
  DupFields = [ "dest_host->dest_ip" ]
}
```