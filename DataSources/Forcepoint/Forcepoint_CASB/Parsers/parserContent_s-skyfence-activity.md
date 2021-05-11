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
    """\sdvc="{1,20}({host}[^"]+)""",
    """\sdvchost="{1,20}({host}[^"]+)""",
    """\srt="{1,20}({time}\d{1,100})""",
    """\sduser="{1,20}({user}[^"]+)""",
    """\sduser="{1,20}[^@]+@({domain}[^".]+)""",
    """\sreason="{1,20}({activity}[^"]+)""",
    """\sdestinationServiceName="({app}[^"]+)"""",
    """\sapp="({app}[^"]+)"""",
    """\srequestClientApplication=({user_agent}.+?)\s\w+=""",
    """\sdst="{1,20}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssrc="{1,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdpriv="{1,20}({privileges}[^"]+)""",
    """\sdeviceProcessName="({object}[^"]+)"{1,20}\s\w+=""",
    """\smsg="{1,20}({additional_info}[^"]+)"""
  ]
}
```