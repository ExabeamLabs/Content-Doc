#### Parser Content
```Java
{
Name = exchange-failed-app-login
  DataType = "failed-app-login"
  Conditions = [ """Imap4""", """Exchange Server""", """,login,""", """"R="""" ]
  Fields = ${ExchangeParserTemplates.exchange-server-app-login.Fields}[ 
    """({event_name}LOGIN ({outcome}failed))""",
    """Error="{1,20}({failure_reason}[^"-]{1,2000}?)\s{0,100}[\-"]""",
  ]

exchange-server-app-login = {
  Vendor = Microsoft
  Product = Exchange
  Lms = Syslog
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)(,[^,]{0,2000}){2},({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({dest_port}\d{1,100}),({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):({src_port}\d{1,100}),({user}[^,]{1,2000})(,[^,]{0,2000}){3},({event_name}[^,]{1,2000}),""",
    """({app}Exchange Server)""",
    """Msg="({additional_info}[^"]{1,2000})""",
  ]
  DupFields = ["event_name->activity"
}
```