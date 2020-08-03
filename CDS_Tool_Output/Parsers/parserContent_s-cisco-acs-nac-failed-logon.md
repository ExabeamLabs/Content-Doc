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
      """\W({time}\w{3}\s+\d{1,2} \d\d:\d\d:\d\d)\s+({host}[\w\-.]+)\s""",
      """"\w+\s+({time}\w+\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+\d\d\d\d)"""",
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
      """, FailureReason=({result_code}\d+)""",
      """\WFailed-Attempt:\s*({failure_reason}[^,]+),"""
    ]
  }
```