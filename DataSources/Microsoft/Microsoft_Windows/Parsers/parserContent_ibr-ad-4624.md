#### Parser Content
```Java
{
Name = ibr-ad-4624
  DataType = "windows-4624"
  Conditions = [ """ibr_ad""", """<custom_condition_cont-7495>""", """,4624,""" ]
  Fields = ${WinParserTemplates.ibr-ad-template.Fields} [
    """,Microsoft-Windows-Security-Auditing,[^\|]+\|(|-|({user}[^\|]+?))\|(|-|({domain}[^\|]+?))\|(|-|({logon_id}[^\|]+?))\|(|-|({target_user_sid}[^\|]+?))\|(|-|({target_user}[^\|]+?))\|(|-|({target_domain}[^\|]+?))\|(|-|({target_logon_id}[^\|]+?))\|(|-|({logon_type}[^\|]+?))\|(|-|({process}[^\|]+?))\|(|-|({auth_package}[^\|]+?))\|(|-|[^\|]+?)\|(|-|({src_host}[^\|]+?))\|(|-|({guid}[^\|]+?))\|(|-|({service}[^\|]+?))\|(|-|[^\|]+?)\|(|-|({key_length}[^\|]+?))\|(|-|({process_id}[^\|]+?))\|(|-|({src_ip}[^\|]+?))\|(({src_port}\d+)|-|)"""
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