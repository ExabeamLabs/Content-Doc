#### Parser Content
```Java
{
Name = q-adfs-auth-failed-2
  DataType = "authentication-failed"
  Conditions = [ """Message=Token validation failed""", """EventIDCode=411""" ]
  Fields = ${MicrosoftParserTemplates.q-adfs-auth.Fields}[
    """Token Type:\s{0,100}({auth_method}.+?)\s{0,100}Client IP:""",
    """Exception details:\s{0,100}({additional_info}.{1,250})""",
    """({src_ip}[a-fA-F\d.:]+)\s{0,100}Error message:""",
    """Error message:\s{0,100}({failure_reason}.+?)\s{0,100}Exception details:""",
  ]
  DupFields = [ "account->user" ]
}
q-adfs-auth = {
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = QRadar
    TimeFormat = "epoch_sec"
    Fields = [
      """\sTimeGenerated=({time}\d{1,100})""",
      """\sEventIDCode=({event_code}\d{1,100})""",
      """\sComputer=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
      """\sUser=({account}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
      """\sDomain=({account_domain}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
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