<h3 class="users"><span>{TR_TITLE}</span></h3>
<!-- BDP: dmarc_entries -->
<table class="firstColFixed">
    <thead>
    <tr>
        <th>{TR_STATUS}</th>
        <th>{TR_CUSTOMER}</th>
        <th>{TR_DOMAIN}</th>
        <th>{TR_POLICY}</th>
        <th>{TR_RECORD}</th>
    </tr>
    </thead>
    <tbody>
    <!-- BDP: dmarc_entry -->
    <tr>
        <td><div class="icon i_{STATUS_ICON}">{STATUS}</div></td>
        <td>{CUSTOMER_NAME}</td>
        <td>{DOMAIN_NAME}</td>
        <td>{POLICY}</td>
        <td><code>{RECORD}</code></td>
    </tr>
    <!-- EDP: dmarc_entry -->
    </tbody>
</table>
<!-- EDP: dmarc_entries -->
<!-- BDP: dmarc_no_entry -->
<div class="static_info">{TR_NO_ENTRY}</div>
<!-- EDP: dmarc_no_entry -->
