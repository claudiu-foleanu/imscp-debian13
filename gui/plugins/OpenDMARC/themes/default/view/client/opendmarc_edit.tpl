<form name="opendmarc_edit_frm" method="post" action="{FORM_ACTION}">
    <input type="hidden" name="csrf_token" value="{CSRF_TOKEN}">
    <table class="firstColFixed">
        <thead>
        <tr>
            <th colspan="2">{TR_DOMAIN}</th>
        </tr>
        </thead>
        <tbody>
        <tr>
            <td>{TR_DOMAIN_NAME}</td>
            <td><span class="bold">{DOMAIN_NAME}</span></td>
        </tr>
        <tr>
            <td>{TR_STATUS}</td>
            <td>{STATUS}</td>
        </tr>
        <tr>
            <td>{TR_RECORD}</td>
            <td><code>{RECORD_PREVIEW}</code></td>
        </tr>
        <tr>
            <td>
                <label for="policy">{TR_POLICY}</label>
                <span class="icon i_help" title="{TR_POLICY_TOOLTIP}"></span>
            </td>
            <td><select name="policy" id="policy">{POLICY_OPTIONS}</select></td>
        </tr>
        <tr>
            <td><label for="subdomain_policy">{TR_SP}</label></td>
            <td><select name="subdomain_policy" id="subdomain_policy">{SUBDOMAIN_POLICY_OPTIONS}</select></td>
        </tr>
        <tr>
            <td>
                <label for="pct">{TR_PCT}</label>
                <span class="icon i_help" title="{TR_PCT_TOOLTIP}"></span>
            </td>
            <td><input type="text" name="pct" id="pct" value="{PCT}" placeholder="{PCT_DEFAULT}" maxlength="3"></td>
        </tr>
        <tr>
            <td><label for="adkim">{TR_ADKIM}</label></td>
            <td><select name="adkim" id="adkim">{ADKIM_OPTIONS}</select></td>
        </tr>
        <tr>
            <td><label for="aspf">{TR_ASPF}</label></td>
            <td><select name="aspf" id="aspf">{ASPF_OPTIONS}</select></td>
        </tr>
        <tr>
            <td>
                <label for="rua">{TR_RUA}</label>
                <span class="icon i_help" title="{TR_REPORT_TOOLTIP}"></span>
            </td>
            <td><input type="text" name="rua" id="rua" value="{RUA}" placeholder="{RUA_DEFAULT}" maxlength="254"></td>
        </tr>
        <tr>
            <td>
                <label for="ruf">{TR_RUF}</label>
                <span class="icon i_help" title="{TR_REPORT_TOOLTIP}"></span>
            </td>
            <td><input type="text" name="ruf" id="ruf" value="{RUF}" placeholder="{RUF_DEFAULT}" maxlength="254"></td>
        </tr>
        </tbody>
    </table>
    <div class="buttons">
        <input name="Submit" type="submit" value="{TR_UPDATE}">
        <button type="submit" name="reset" value="1">{TR_RESET}</button>
        <a class="link_as_button" href="opendmarc">{TR_CANCEL}</a>
    </div>
</form>
