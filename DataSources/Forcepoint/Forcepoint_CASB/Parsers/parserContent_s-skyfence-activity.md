#### Parser Content
```Java
{
Name = s-skyfence-activity
  Vendor = Forcepoint 
  Product = Forcepoint CASB
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ "CEF", "Skyfence", """|Activity|""" ]
  Fields = [
    """\sdvc="+({host}[^"]+)""",
    """\sdvchost="+({host}[^"]+)""",
    """\srt="+({time}\d+)""",
    """\sduser="+({user}[^"]+)""",
    """\sduser="+[^@]+@({domain}[^".]+)""",
    """\sreason="+({activity}[^"]+)""",
    """\sdestinationServiceName="({app}[^"]+)"""",
    """\sapp="({app}[^"]+)"""",
    """\srequestClientApplication=({user_agent}.+?)\s\w+=""",
    """\sdst="+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrc="+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdpriv="+({privileges}[^"]+)""",
    """\sdeviceProcessName="({object}[^"]+)"+\s\w+=""",
    """\smsg="+({additional_info}[^"]+)"""
  ]
}
```