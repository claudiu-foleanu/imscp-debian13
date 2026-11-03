<h3 class="domains"><span>{TR_TITLE}</span></h3>
<p class="hint">{TR_HINT}</p>
<br>
<!-- BDP: dmarc_entries -->
<table class="firstColFixed">
    <thead>
    <tr>
        <th>{TR_STATUS}</th>
        <th>{TR_DOMAIN}</th>
        <th>{TR_DNS_NAME}</th>
        <th>{TR_POLICY}</th>
        <th>{TR_RECORD}</th>
        <th>{TR_NOTES}</th>
        <th>{TR_ACTIONS}</th>
    </tr>
    </thead>
    <tbody>
    <!-- BDP: dmarc_entry -->
    <tr>
        <td><div class="icon i_{STATUS_ICON}">{STATUS}</div></td>
        <td>{DOMAIN_NAME}</td>
        <td>{DNS_NAME}</td>
        <td>{POLICY}</td>
        <td><code>{RECORD}</code></td>
        <td>{NOTES}</td>
        <td>
            <!-- BDP: dmarc_edit_link -->
            <a class="icon i_edit" href="{EDIT_URL}" title="{TR_EDIT}">{TR_EDIT}</a>
            <!-- EDP: dmarc_edit_link -->
        </td>
    </tr>
    <!-- EDP: dmarc_entry -->
    </tbody>
</table>
<!-- EDP: dmarc_entries -->
<!-- BDP: dmarc_no_entry -->
<div class="static_info">{TR_NO_ENTRY}</div>
<!-- EDP: dmarc_no_entry -->
