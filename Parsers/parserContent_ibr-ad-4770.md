#### Parser Content
```Java
{
Name = ibr-ad-4770
  DataType = "windows-4770"
  Conditions = [ """ibr_ad""", """<custom_condition_cont-7495>""", """,4770,""" ]
  Fields = ${WinParserTemplates.ibr-ad-template.Fields} [
    """,Microsoft-Windows-Security-Auditing,[^\|]+\|(|-|({domain}[^\|]+?))\|(|-|({service_name}[^\|]+?))\|(|-|({service_sid}[^\|]+?))\|(|-|({ticket_options}[^\|]+?))\|(|-|({encryption_type}[^\|]+?))\|(|-|({src_ip}[^\|]+?))\|(({src_port}\d+)|-|)"""
  ]
}
```