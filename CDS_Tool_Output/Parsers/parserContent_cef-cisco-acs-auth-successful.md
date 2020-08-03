#### Parser Content
```Java
{
Name = cef-cisco-acs-auth-successful
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = [ """|CISCO|Cisco Secure ACS|""", """|Authentication succeeded|""" , """ad.Action=Login""" ]
  Fields = [
      """\srt=({time}\d+)""",
      """\sdvc=({host}[^\s]+)""",
      """\sdvchost=({host}[^\s]+)""",
      """\sshost=(?:|({src_host}.+?))\s\w+=""",
      """\ssrc=(?:|({src_ip}.+?))\s\w+=""",
      """\ssuser=(({domain}[^\\]+)\\+)?({user}[^=]+)\s\w+=""",
      """\sdst=(?:|({dest_ip}.+?))\s\w+=""",
      """AuthenticationMethod=(?:|({auth_method}.+?))\s[\w.]+="""
	]
}
```