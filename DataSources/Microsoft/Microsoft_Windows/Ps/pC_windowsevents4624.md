#### Parser Content
```Java
{
Name = windows-events-4624
  DataType = "windows-4624"
  Conditions = [ """subject.logon_id""", """EventID""", """4624""" ]
  Fields = ${WinParserTemplates.windows-events-2.Fields} [
       """detailed_authentication_information.authentication_package":"({auth_package}[^"]{1,2000})""",
       """network_information.source_network_address":"(-|({src_ip}[^"]{1,2000}))""""
       """network_information.workstation_name":"(-|({src_host_windows}[^"]{1,2000}))"""",
       """"message":"({event_name}[^"]{1,2000})"""",
       """logon_process":"({auth_process}[^"]{1,2000})"""",
       """key_length":"({key_length}\d{1,2000})""""
    ]

windows-events-2 = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
    """"{1,20}EventID"{1,20}:"{1,20}({event_code}\d{1,100})""",
    """"{1,20}subject.logon_id"{1,20}:"{1,20}({logon_id}[^"]{1,2000})""",
    """"{1,20}subject.security_id"{1,20}:"{1,20}({user_sid}[^"]{1,2000})""",
    """"{1,20}process_information.process_name"{1,20}:"{1,20}({process}({directory}[^"]{0,2000})\\\\({process_name}[^"]{1,2000}))""",
    """"{1,20}process_information.process_id"{1,20}:"{1,20}({process_id}[^"]{1,2000})""",
    """"{1,20}Computer"{1,20}:"{1,20}({host}[^"]{1,2000})""",
    """"{1,20}subject.account_name"{1,20}:"{1,20}(-|({user_email}({user}[^@]{1,2000})@({domain}[^"]{1,2000}))|({=user}[^"]{1,2000}))""",
    """"{1,20}network_information.source_port"{1,20}:"{1,20}(-|({src_port}\d{1,100}))""",
    """"{1,20}new_logon.account_domain"{1,20}:"{1,20}({domain}[^"]{1,2000})""",
    """"message"{1,20}:"{1,20}({additional_info}[^"]{1,2000})""",
    """"{1,20}ProviderName"{1,20}:"{1,20}({provider_name}[^"]{1,2000})""",
    """"{1,20}logon_information.logon_type"{1,20}:"{1,20}({logon_type}\d{1,100})"""
	
}
```