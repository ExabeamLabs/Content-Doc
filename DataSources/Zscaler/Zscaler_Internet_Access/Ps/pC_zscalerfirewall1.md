#### Parser Content
```Java
{
Name = zscaler-firewall-1
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Direct
  DataType = "network-connection"
  TimeFormat="MMM dd HH:mm:ss yyyy"
  Conditions = [""""department":""", """"avgduration":""", """"locationname":""", """"event" :{"""]
  Fields = [
     """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
     """({time}\w{3}\s{1,100}\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
     """"action":"({outcome}[^"]{1,2000})"""",
     """user":"(({user_email}[^@]{1,2000}@[^"]{0,2000})|({user}[^"]{1,2000}))"""",
     """csip":"({src_ip}[\da-fA-F.:]{1,2000})"""",
     """sdip":"({dest_ip}[\da-fA-F.:]{1,2000})"""",
     """sdport":"({dest_port}[^"]{1,2000})"""",
     """csport":"({src_port}[^"]{1,2000})"""",
     """proto":"({protocol}[^"]{1,2000})"""",
     """inbytes":"({bytes_in}[^"]{1,2000})"""",
     """outbytes":"({bytes_out}[^"]{1,2000})"""",
     """devicehostname":"(NA|\s{1,200}|({host}[^"]{1,2000}))""""
  ]
  DupFields = ["outcome->action"]
 

}
```