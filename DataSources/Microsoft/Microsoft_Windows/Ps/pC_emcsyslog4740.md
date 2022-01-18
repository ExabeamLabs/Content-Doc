#### Parser Content
```Java
{
Name = emc-syslog-4740
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Syslog
  DataType = "windows-account-lockout"
  TimeFormat = "epoch"
  Conditions = [ "__li_source_path=", "A user account was locked out", """eventid="4740"""" ]
  Fields = [
    """({event_name}A user account was locked out)""",
    """\W__li_source_path="({host}[\w\.-]{1,2000})"""",
    """({event_code}4740)""",
    """\Weventrecordid="({record_id}\d{1,100})"""",
    """Subject:.+?Account Name:\s{1,100}({caller_user}.+?)\s{1,100}Account Domain:\s{1,100}(?=\w)({caller_domain}.+?)\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",  
    """Locked Out:\s{1,100}Security ID:\s{1,100}(%\{)?({user_sid}([\w\d\-]{1,2000}?)|([^\s]{1,2000}))\}?\s{1,100}Account Name:\s{1,100}(?=\w)({user}.+?)\s{1,100}Additional""",
    """Caller Computer Name:\s{1,100}(\\+)?({src_host}[^\#\s",]{1,2000})"""    
  ]
  DupFields=[ "host->dest_host", "caller_domain->domain" ]


}
```