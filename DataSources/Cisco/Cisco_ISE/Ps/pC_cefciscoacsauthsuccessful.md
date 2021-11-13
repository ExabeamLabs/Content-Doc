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
      """\srt=({time}\d{1,100})""",
      """\sdvc=({host}[^\s]{1,2000})""",
      """\sdvchost=({host}[^\s]{1,2000})""",
      """\sshost=(?:|({src_host}.+?))\s\w+=""",
      """\ssrc=(?:|({src_ip}.+?))\s\w+=""",
      """\ssuser=(({domain}[^\\]{1,2000})\\+)?({user}[^=]{1,2000})\s\w+=""",
      """\sdst=(?:|({dest_ip}.+?))\s\w+=""",
      """AuthenticationMethod=(?:|({auth_method}.+?))\s[\w.]{1,2000}="""
	]


}
```