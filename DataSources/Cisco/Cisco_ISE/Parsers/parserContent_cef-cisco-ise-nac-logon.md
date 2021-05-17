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
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sduser=(?:|(({domain}[^\\=]{1,2000})\\+)?({user}(?:({computer_name}([A-F0-9]{2}\-){5}[A-F0-9]{2})|.+?)))\scn1=""",
    """\sdhost=({dest_host}[^\s]{1,2000})""",
    """\sdst=({dest_ip}[^\s]{1,2000})""",
    """\sdst=({auth_server}[^\s]{1,2000})""",
    """\sshost=({src_host}[^\s]{1,2000})""",
    """\ssrc=({src_ip}[^\s]{1,2000})"""
  ]
}
```