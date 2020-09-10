#### Parser Content
```Java
{
Name = q-aruba-nac-logon-6
  DataType = "nac-logon"
  Conditions = [ """ Guest """, """Common.Request-Timestamp=""" ]
}
${HPEParserTemplates.q-aruba-nac-logon}{
  Name = q-aruba-nac-logon-7
  TimeFormat="yyyy-MM-dd HH:mm:ss-SS"
  DataType = "nac-logon"
  Conditions = [ """Authenticated]""", """Common.Request-Timestamp=""" ]
}



  {
    Name = s-ping-sso
    Vendor = Ping Identity
    Product = Ping Identity
    Lms = Splunk
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """event=SSO""", "status=success"," pfhost=" ]
    Fields = [
    """\sip=(?:|({src_ip}.+?))\s\w+=""",
    """exabeam_raw=.*?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\spfhost=(?:|({host}.+?))\s\w+=""",
    """\ssubject="(?:|({user}[^"]+))"""",
    """\sapp=(?:|({app}.+?))\s\w+="""
    ]
  }
```