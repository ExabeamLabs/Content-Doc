#### Parser Content
```Java
{
Name = logstash-4624
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4624"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = ["An account was successfully logged on", """"event_id":"4624"""", """"new_logon-LogonID":""""]
    Fields = [
      """"time":"({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""""
      """"host":"({host}[^"]{1,2000})\s{0,100}"""
      """({event_name}An account was successfully logged on)""",
      """({event_code}4624)""",
      """"logon_type":"\s{0,100}({logon_type}\d{1,100})""",
      """"new_logon-AccountName":"\s{0,100}({user}[^"]{1,2000})\s{0,100}""""
      """"new_logon-AccountDomain":"\s{0,100}({domain}[^"]{1,2000})\s{0,100}""""
      """"process_information-ProcessName":"(-|\s{0,100}({process}[^"]{1,2000}))\s{0,100}""""
      """"network_information-WorkstationName":"\s{0,100}(-|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host_windows}[^"]{1,2000}))\s{0,100}""""
      """"network_information-SourceNetworkAddress":"\s{0,100}(?:-|({src_ip}[\w:.]{1,2000}))\s{0,100}""""
      """"detailed_authentication_information-LogonProcess":"\s{0,100}({auth_process}[^"]{1,2000})\s{0,100}""""
      """"detailed_authentication_information-AuthenticationPackage":"\s{0,100}({auth_package}[^"]{1,2000})\s{0,100}""""
      """"new_logon-LogonID":"\s{0,100}({logon_id}[^"]{1,2000})\s{0,100}""""
      """"new_logon-SecurityID":"\s{0,100}({user_sid}[^"]{1,2000})\s{0,100}"""",
      """"cmpny.source.ip":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """"subject-SecurityID":"\s{0,100}({subject_sid}[^"]{1,2000})\s{0,100}""""
      """KeyLength":"\s{0,100}({key_length}[^"]{1,2000})\s{0,100}""""
    ]
    DupFields = ["src_host_windows->dest_host", "user->account"]
  

}
```