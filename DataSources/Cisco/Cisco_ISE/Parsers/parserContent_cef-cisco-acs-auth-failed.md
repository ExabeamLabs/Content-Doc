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
      """\srt=({time}\d+)""",
      """\sdvc=({host}[^\s]+)""",
      """\sdvchost=({host}[^\s]+)""",
      """\ssrc=(?:|({src_ip}.+?))\s\w+=""",
      """\ssuser=(({domain}[^\\]+)\\+)?({user}[^=]+)\s\w+=""",
      """\sdst=(?:|({dest_ip}.+?))\s\w+=""",
      """\sdhost=(?:|({dest_host}.+?))\s\w+=""",
      """AuthenticationMethod=(?:|({auth_method}.+?))\s[\w.]+=""",
      """FailureReason=(?:|({failure_reason}.+?))\s[\w.]+="""
	]
}
```