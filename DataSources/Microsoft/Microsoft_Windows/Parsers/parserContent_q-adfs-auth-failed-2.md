#### Parser Content
```Java
{
Name = q-adfs-auth-failed-2
  DataType = "authentication-failed"
  Conditions = [ """Message=Token validation failed""", """EventIDCode=411""" ]
  Fields = ${MicrosoftParserTemplates.q-adfs-auth.Fields}[
    """Token Type:\s*({auth_method}.+?)\s*Client IP:""",
    """Exception details:\s*({additional_info}.{1,250})""",
    """({src_ip}[a-fA-F\d.:]+)\s*Error message:""",
    """Error message:\s*({failure_reason}.+?)\s*Exception details:""",
  ]
  DupFields = [ "account->user" ]
}
q-adfs-auth = {
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = QRadar
    TimeFormat = "epoch_sec"
    Fields = [
      """\sTimeGenerated=({time}\d+)""",
      """\sEventIDCode=({event_code}\d+)""",
      """\sComputer=({host}.+?)(\s+\w+=|\s*$)""",
      """\sUser=({account}.+?)(\s+\w+=|\s*$)""",
      """\sDomain=({account_domain}.+?)(\s+\w+=|\s*$)""",
      """\sMessage=({event_name}[^=\.]+)""",
      """<IpAddress>({additional_info}[^<]+)</IpAddress>""",
      """<IpAddress>({src_ip}[a-fA-F\d.:]+)</IpAddress>""",
      """({src_ip}[a-fA-F\d.:]+)</IpAddress>""",
      """<ClaimsProvider>(?:N\/A|({domain}[^<]+))</ClaimsProvider>""",
      """<UserId>(({domain}[^<\\]+)\\+)?({user}(?!N\/A)[^<\\]+)</UserId>""",
      """<FailureType>(?:None|({failure_reason}[^<]+))</FailureType>""",
      """<Server>({auth_server}[^<]+)</Server>""",
      """:({service}[^:>]+)</RelyingParty>""",
      """<PrimaryAuth>(N\/A|[^<]+?\/({auth_method}[^<\/]+))</PrimaryAuth>""",
    ]

```