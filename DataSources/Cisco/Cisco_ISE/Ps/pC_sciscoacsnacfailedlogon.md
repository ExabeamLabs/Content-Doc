#### Parser Content
```Java
{
Name = s-cisco-acs-nac-failed-logon
    Vendor = Cisco
    Product = Cisco ISE
    Lms = Splunk
    DataType = "nac-failed-logon"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
    Conditions = [ """ CSCOacs_Failed_Attempts """ ]
    Fields = [
      """\W({time}\w{3}\s{1,100}\d{1,2} \d\d:\d\d:\d\d)\s{1,100}({host}[\w\-.]{1,2000})\s""",
      """"\w+\s{1,100}({time}\w+\s{1,100}\d{1,2}\s{1,100}\d\d:\d\d:\d\d\s{1,100}\d\d\d\d)"""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
      """, User=({user}[^,]{1,2000}),""",
      """, UserName =(host\/)?(({domain}[^\s\\]{1,2000})\\+)?({user}[^,]{1,2000}),""",
      """, Calling-Station-ID=({dest_host}[^,]{1,2000})""",
      """, AD-User-Candidate-Identities=({dest_host}[^@,]{1,2000})""",
      """, AD-User-Candidate-Identities=({computer_name}[^@,]{1,2000})""",
      """, NetworkDeviceName =({network}[^,]{1,2000}),""",
      """, Device IP Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """, DestinationIPAddress=({auth_server}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """, NetworkDeviceGroups=Location:All Locations:({location}[^,]{1,2000})""",
      """, FailureReason=({result_code}\d{1,100})""",
      """\WFailed-Attempt:\s{0,100}({failure_reason}[^,]{1,2000}),"""
    ]
  

}
```