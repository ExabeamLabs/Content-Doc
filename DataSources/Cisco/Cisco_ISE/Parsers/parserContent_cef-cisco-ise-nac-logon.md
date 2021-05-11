#### Parser Content
```Java
{
Name = cef-cisco-ise-nac-logon
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|CISCO|ISE|""","""msg=NOTICE Passed-Authentication""","""app=Radius"""  ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\srt=({time}[A-Za-z]{3} \d\d \d{4} \d\d:\d\d:\d\d)""",
    """\sdvchost=({host}[^\s]+)""",
    """\sduser=(?:|(({domain}[^\\=]+)\\+)?({user}(?:({computer_name}([A-F0-9]{2}\-){5}[A-F0-9]{2})|.+?)))\scn1=""",
    """\sdhost=({dest_host}[^\s]+)""",
    """\sdst=({dest_ip}[^\s]+)""",
    """\sdst=({auth_server}[^\s]+)""",
    """\sshost=({src_host}[^\s]+)""",
    """\ssrc=({src_ip}[^\s]+)"""
  ]
}
```