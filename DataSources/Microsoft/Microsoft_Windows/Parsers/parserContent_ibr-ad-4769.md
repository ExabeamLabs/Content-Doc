#### Parser Content
```Java
{
Name = ibr-ad-4769
  DataType = "windows-4769"
  Conditions = [ """ibr_ad""", """<custom_condition_cont-7495>""", """,4769,""" ]
  Fields = ${WinParserTemplates.ibr-ad-template.Fields} [
    """,Microsoft-Windows-Security-Auditing,[^\|]+\|(|-|({domain}[^\|]+?))\|(|-|({dest_host}[^\|]+?))\|(|-|({service_sid}[^\|]+?))\|(|-|({ticket_options}[^\|]+?))\|(|-|({encryption_type}[^\|]+?))\|(|-|({src_ip}[^\|]+?))\|(|-|({src_port}[^\|]+?))\|(|-|({result_code}[^\|]+?))\|(|-|({logon_guid}[^\|]+?))\|"""
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