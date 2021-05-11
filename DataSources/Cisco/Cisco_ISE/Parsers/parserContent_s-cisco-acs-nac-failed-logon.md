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
      """\W({time}\w{3}\s{1,100}\d{1,2} \d\d:\d\d:\d\d)\s{1,100}({host}[\w\-.]+)\s""",
      """"\w+\s{1,100}({time}\w+\s{1,100}\d{1,2}\s{1,100}\d\d:\d\d:\d\d\s{1,100}\d\d\d\d)"""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
      """, User=({user}[^,]+),""",
      """, UserName=(host\/)?(({domain}[^\s\\]+)\\+)?({user}[^,]+),""",
      """, Calling-Station-ID=({dest_host}[^,]+)""",
      """, AD-User-Candidate-Identities=({dest_host}[^@,]+)""",
      """, AD-User-Candidate-Identities=({computer_name}[^@,]+)""",
      """, NetworkDeviceName=({network}[^,]+),""",
      """, Device IP Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """, DestinationIPAddress=({auth_server}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """, NetworkDeviceGroups=Location:All Locations:({location}[^,]+)""",
      """, FailureReason=({result_code}\d{1,100})""",
      """\WFailed-Attempt:\s{0,100}({failure_reason}[^,]+),"""
    ]
  }
```