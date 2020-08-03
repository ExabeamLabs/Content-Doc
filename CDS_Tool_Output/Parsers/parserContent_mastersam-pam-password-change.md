#### Parser Content
```Java
{
Name = mastersam-pam-password-change
  DataType = "password-change"
  Conditions = [ """ Activity:reset_password_account """ ]
  Fields = ${MasterSAMParserTemplates.mastersam-pam-events.Fields} [
    """account=({target_user}[^"\s]+)""",
  ]
}
```