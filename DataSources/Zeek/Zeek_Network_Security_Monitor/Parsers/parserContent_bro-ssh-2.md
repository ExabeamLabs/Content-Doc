#### Parser Content
```Java
{
Name = bro-ssh-2
  Product = Zeek Network Security Monitor
  DataType = "ssh-login"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"server":"SSH""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"direction":"({direction}[^"]+)""",
    """"client":"({client}[^"]+)""",
    """"server":"({server}[^"]+)""",
    """"auth_success":({outcome}[^,]+)""",
    """"auth_attempts":({auth_attempts}\d+)""",
  ]
}
json-bro-activity = {
  Vendor = Zeek
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
    """"ts\\?"+:[\[\\]*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})"""
    #""""ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"+:\\?"+({conn_id}[^"]+)""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}\d+)""",
    """"proto\\?"+:\\?"+({protocol}[^"]+)""",
  ]

```