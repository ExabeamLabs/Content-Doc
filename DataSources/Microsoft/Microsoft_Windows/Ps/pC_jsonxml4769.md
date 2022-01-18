#### Parser Content
```Java
{
Name = json-xml-4769
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4769"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """"EventID":"4769"""", """<Data Name ='""" ]
    Fields = [
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"EventID":"({event_code}\d{1,100})""",
      """"Computer":"({host}[^"]{1,2000})""",
      """<Data Name ='Status'>({result_code}[^<]{1,2000})</Data>""",
      """<Data Name ='ServiceName'>({dest_host}[^<]{1,2000}\$)</Data>""",
      """<Data Name ='ServiceName'>({service_name}[^<]{1,2000})</Data>""",
      """<Data Name ='TicketOptions'>({ticket_options}[^<]{1,2000})</Data>""",
      """<Data Name ='TicketEncryptionType'>({ticket_encryption_type}[^<]{1,2000})</Data>""",
      """<Data Name ='TargetUserName'>(?=\w)({user}[^<]{1,2000})</Data>""",
      """<Data Name ='TargetDomainName'>(?=\w)({domain}[^<]{1,2000})</Data>""",
      """<Data Name ='IpAddress'>(::[\w]{1,2000}:)?({src_ip}[a-fA-F:\d.]{1,2000})"""
    ]
  

}
```