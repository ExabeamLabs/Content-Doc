#### Parser Content
```Java
{
Name = s-digitalguardian-print-activity-2
  Conditions = [ """Operation="22"""" , """Agent_UTC_Time=""" ]
}
splunk-digitalguardian-print-activity = {
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Fields = [
    """(\s|exabeam_\w+=)?(Agent_UTC_Time|Server_UTC_Timestamp)="({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))"""",
    """exabeam_host=([^@=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """(\s|exabeam_\w+=)Computer_Name ="([^\/"\\]{1,2000}(\/|\\))?({host}[^"]{1,2000})"""",
    """(\s|exabeam_\w+=)User_Name ="(?:|(({domain}[^"\/\\]{1,2000})[\/\\]{1,2000})?({user}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Domain_Name ="(?:|({domain}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Printer="(?:\\+[^"]{1,2000}|({printer_name}[^"]{1,2000}))""",
    """(\s|exabeam_\w+=)Printer="\\+(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\\]{1,2000}))\\+""",
    """(\s|exabeam_\w+=)Printer="\\+[^\\]{1,2000}\\+(?:(ip_)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\{?({printer_name}[^:,"}]{1,2000}))""",
    """(\s|exabeam_\w+=)Source_File="(?:|({object}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Bytes_Written="(?:|({bytes}\d{1,100}))"""",
    """Operation_ID="({event_code}[^"]{1,2000})""""
  ]
  DupFields = [ "host->src_host" ]}
```