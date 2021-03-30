#### Parser Content
```Java
{
Name = ibr-ad-4771
  DataType = "usb-activity"
  Conditions = [ """ibr_ad""", """<custom_condition_cont-7495>""", """,4771,""" ]
  Fields = ${WinParserTemplates.ibr-ad-template.Fields} [
    """,Microsoft-Windows-Security-Auditing,[^\|]+\|(|-|({user_sid}[^\|]+?))\|(|-|({service_name}[^\|]+?))\|(|-|({ticket_options}[^\|]+?))\|(|-|({result_code}[^\|]+?))\|(|-|({auth_type}[^\|]+?))\|(|-|({src_ip}[^\|]+?))\|(({src_port}\d+)|-|)"""
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