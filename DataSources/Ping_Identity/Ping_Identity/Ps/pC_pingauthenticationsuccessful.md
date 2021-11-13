#### Parser Content
```Java
{
Name = ping-authentication-successful
  DataType = "authentication-successful"
  Conditions = [ """"source": "PINGID"""",""""type": "user"""",""""status": "POLICY"""",""""message":""",""""resources":""",""""client":""" ]
  Fields = ${PingParserTemplates.ping-authentication_events.Fields}[
    """"status":\s{0,100}"({outcome}POLICY)""",
    """IP Address:\s{0,100}({src_ip}[A-Fa-f\d.:]{1,2000})""",
    """Accessing Device UserAgent:\s{0,100}(N\/A|({user_agent}[^:]{1,2000}))\\[nt]"""
  ]

ping-authentication_events = {
    Vendor = Ping Identity
    Product = Ping Identity
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"recorded":\s{1,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """"name":\s"({user}[^"]{1,2000})"""",
    
}
```