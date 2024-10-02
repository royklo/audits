$improvementsParams = @{
    method = "GET"
    uri    = "https://graph.microsoft.com/beta/security/secureScoreControlProfiles?`$filter=controlCategory eq 'Identity'"
}
$improvements = Invoke-MgGraphRequest @improvementsParams
$n = 3
$recommendations = $improvements.value 