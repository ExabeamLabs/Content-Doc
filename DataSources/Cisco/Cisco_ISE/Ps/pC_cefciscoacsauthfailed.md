#### Parser Content
```Java
{
Name = cef-cisco-acs-auth-failed
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "epoch"
  Conditions = [ """|CISCO|Cisco Secure ACS|""", """|Authentication failed|""" , """ad.Action=Login""" ]
  Fields = [
      """\srt=({time}\d{1,100})""",
      """\sdvc=({host}[^\s]{1,2000})""",
      """\sdvchost=({host}[^\s]{1,2000})""",
      """\ssrc=(?:|({src_ip}.+?))\s\w+=""",
      """\ssuser=(({domain}[^\\]{1,2000})\\+)?({user}[^=]{1,2000})\s\w+=""",
      """\sdst=(?:|({dest_ip}.+?))\s\w+=""",
      """\sdhost=(?:|({dest_host}.+?))\s\w+=""",
      """AuthenticationMethod=(?:|({auth_method}.+?))\s[\w.]{1,2000}=""",
      """FailureReason=(?:|({failure_reason}.+?))\s[\w.]{1,2000}="""
	]


}
```