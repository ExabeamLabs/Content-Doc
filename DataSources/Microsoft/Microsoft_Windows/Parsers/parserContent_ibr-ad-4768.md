#### Parser Content
```Java
{
Name = ibr-ad-4768
  DataType = "windows-4768"
  Conditions = [ """ibr_ad""", """<custom_condition_cont-7495>""", """,4768,""" ]
  Fields = ${WinParserTemplates.ibr-ad-template.Fields} [
    """,Microsoft-Windows-Security-Auditing,[^\|]+\|(|-|({domain}[^\|]+?))\|(|-|({user_sid}[^\|]+?))\|(|-|({dest_host}[^\|]+?))\|(|-|({service_sid}[^\|]+?))\|(|-|({ticket_options}[^\|]+?))\|(|-|({result_code}[^\|]+?))\|(|-|({encryption_type}[^\|]+?))\|(|-|({auth_type}[^\|]+?))\|(|-|({dest_ip}[^\|]+?))\|(({dest_port}\d+)|-|)"""
  ]
}
ibr-ad-template = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """,({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4\d\d\d),""",
    """,Microsoft-Windows-Security-Auditing,([^,]*,){2}(({user_sid}S-\d[^,\|]+)|({user}[^@,\|]+)(@({domain}[^,\|]+))?)"""
  ]

```