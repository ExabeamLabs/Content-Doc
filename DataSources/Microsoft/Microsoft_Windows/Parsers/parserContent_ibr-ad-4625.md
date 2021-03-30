#### Parser Content
```Java
{
Name = ibr-ad-4625
  DataType = "windows-failed-logon"
  Conditions = [ """ibr_ad""", """<custom_condition_cont-7495>""", """,4625,""" ]
  Fields = ${WinParserTemplates.ibr-ad-template.Fields} [
    """,Microsoft-Windows-Security-Auditing,[^\|]+\|(|-|({user}[^\|]+?))\|(|-|({domain}[^\|]+?))\|(|-|({logon_id}[^\|]+?))\|(|-|({target_user_sid}[^\|]+?))\|(|-|({target_user}[^\|]+?))\|(|-|({target_domain}[^\|]+?))\|(|-|({status}[^\|]+?))\|(|-|({result_code}[^\|]+?))\|(|-|({sub_status}[^\|]+?))\|(|-|({logon_type}[^\|]+?))\|(|-|({logon_process}[^\|]+?))\|(|-|({auth_package}[^\|]+?))\|(|-|({src_host}[^\|]+?))\|(|-|({services}[^\|]+?))\|(|-|[^\|]+?)\|(|-|({key_length}[^\|]+?))\|(|-|({process_id}[^\|]+?))\|(|-|({process_name}[^\|]+?))\|(|-|({src_ip}[^\|]+?))\|(({src_port}\d+)|-|)"""
  ]
}
```