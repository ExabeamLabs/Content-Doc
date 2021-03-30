#### Parser Content
```Java
{
Name = ibr-ad-4648
  DataType = "windows-account-switch"
  Conditions = [ """ibr_ad""", """<custom_condition_cont-7495>""", """,4648,""" ]
  Fields = ${WinParserTemplates.ibr-ad-template.Fields} [
    """,Microsoft-Windows-Security-Auditing,[^\|]+\|(|-|({user}[^\|]+?))\|(|-|({domain}[^\|]+?))\|(|-|({logon_id}[^\|]+?))\|(|-|({guid}[^\|]+?))\|(|-|({account}[^\|]+?))\|(|-|({target_domain}[^\|]+?))\|(|-|({target_guid}[^\|]+?))\|(|-|({dest_host}[^\|]+?))\|(|-|({target_info}[^\|]+?))\|(|-|({process_id}[^\|]+?))\|(|-|({process_name}[^\|]+?))\|(|-|({src_ip}[^\|]+?))\|(({src_port}\d+)|-|)"""
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