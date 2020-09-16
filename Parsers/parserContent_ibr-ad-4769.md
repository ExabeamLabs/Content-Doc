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
```