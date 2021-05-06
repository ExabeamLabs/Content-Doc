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
      """"time":"({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""""
      """"host":"({host}[^"]+)\s*"""
      """({event_name}An account was successfully logged on)""",
      """({event_code}4624)""",
      """"logon_type":"\s*({logon_type}\d+)""",
      """"new_logon-AccountName":"\s*({user}[^"]+)\s*""""
      """"new_logon-AccountDomain":"\s*({domain}[^"]+)\s*""""
      """"process_information-ProcessName":"(-|\s*({process}[^"]+))\s*""""
      """"network_information-WorkstationName":"\s*(-|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host_windows}[^"]+))\s*""""
      """"network_information-SourceNetworkAddress":"\s*(?:-|({src_ip}[\w:.]+))\s*""""
      """"detailed_authentication_information-LogonProcess":"\s*({auth_process}[^"]+)\s*""""
      """"detailed_authentication_information-AuthenticationPackage":"\s*({auth_package}[^"]+)\s*""""
      """"new_logon-LogonID":"\s*({logon_id}[^"]+)\s*""""
      """"new_logon-SecurityID":"\s*({user_sid}[^"]+)\s*"""",
      """"cmpny.source.ip":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """"subject-SecurityID":"\s*({subject_sid}[^"]+)\s*""""
      """KeyLength":"\s*({key_length}[^"]+)\s*""""
    ]
    DupFields = ["src_host_windows->dest_host", "user->account"]
  }
```