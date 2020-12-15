#### Parser Content
```Java
{
Name = cef-okta-account-password-reset
  DataType = "account-password-reset"
  Conditions = ["""CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Okta""", """"eventType":"system.email.password_reset.sent_message""""]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """target(s)?"+:[^\]]+?"+type"+:"+User"+[^\]\}]+?"+(alternateId|emailAddress)"+:(null|"+({target_user}[^"@]+@({target_domain}[^"]+)))""",
    """target(s)?"+:[^\]]+?"+type"+:"+User"+[^\]\}]+?"+(alternateId|emailAddress)"+:(null|"+(({target_domain}[^\\\/]+)[\/\\]+)?({target_user}[^"]+))"""
  ]
}
```