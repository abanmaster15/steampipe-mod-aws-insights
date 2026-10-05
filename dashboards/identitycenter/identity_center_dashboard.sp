variable "identity_center_connection" {
  type        = string
  description = "Steampipe connection for the AWS Organizations management (or delegated admin) account, where the IAM Identity Center APIs are reachable."
  default     = "aws_bdp_gen"
}

locals {
  identity_center_common_tags = {
    service = "AWS/IdentityCenter"
  }

  # Shared CTEs for IAM Identity Center queries.
  # aws_ssoadmin_account_assignment requires literal permission_set_arn and
  # target_account_id quals (the plugin rejects them as join parameters), so
  # each (permission set, account) pair is looked up with a correlated subquery.
  identity_center_base_sql = <<-EOQ
    with instance as (
      select distinct arn, identity_store_id from aws_ssoadmin_instance
    ),
    users as materialized (
      select distinct
        u.id,
        u.name,
        u.display_name,
        (select e ->> 'Value' from jsonb_array_elements(u.emails) e order by (e ->> 'Primary')::bool desc nulls last limit 1) as email
      from
        aws_identitystore_user u
        join instance i on u.identity_store_id = i.identity_store_id
    ),
    groups as materialized (
      select distinct g.id, g.name, g.description
      from
        aws_identitystore_group g
        join instance i on g.identity_store_id = i.identity_store_id
    ),
    memberships as materialized (
      select distinct m.group_id, m.member_id
      from
        aws_identitystore_group_membership m
        join instance i on m.identity_store_id = i.identity_store_id
    ),
    permission_sets as materialized (
      select distinct p.arn, p.name, p.description, p.session_duration, p.inline_policy
      from
        aws_ssoadmin_permission_set p
        join instance i on p.instance_arn = i.arn
    ),
    accounts as materialized (
      select id, name from aws_organizations_account
    ),
    assignment_lookups as materialized (
      select
        ps.arn as permission_set_arn,
        ps.name as permission_set_name,
        a.id as account_id,
        a.name as account_name,
        (
          select jsonb_agg(jsonb_build_object('principal_type', aa.principal_type, 'principal_id', aa.principal_id))
          from aws_ssoadmin_account_assignment aa
          where aa.permission_set_arn = ps.arn and aa.target_account_id = a.id
        ) as principals
      from
        permission_sets ps
        cross join accounts a
    ),
    assignments as (
      select
        l.permission_set_arn,
        l.permission_set_name,
        l.account_id,
        l.account_name,
        p ->> 'principal_type' as principal_type,
        p ->> 'principal_id' as principal_id
      from
        assignment_lookups l,
        jsonb_array_elements(l.principals) p
      where
        l.principals is not null
    )
  EOQ
}

dashboard "identity_center_dashboard" {

  title              = "AWS IAM Identity Center Dashboard"
  documentation      = file("./dashboards/identitycenter/docs/identity_center_dashboard.md")
  search_path_prefix = [var.identity_center_connection]

  tags = merge(local.identity_center_common_tags, {
    type = "Dashboard"
  })

  container {

    card {
      query = query.identity_center_user_count
      width = 2
    }

    card {
      query = query.identity_center_group_count
      width = 2
    }

    card {
      query = query.identity_center_permission_set_count
      width = 2
    }

    card {
      query = query.identity_center_account_assignment_count
      width = 2
    }

    card {
      query = query.identity_center_users_without_access_count
      width = 2
    }

    card {
      query = query.identity_center_unassigned_permission_set_count
      width = 2
    }

  }

  container {

    title = "Analysis"

    chart {
      title = "Assignments by Account"
      query = query.identity_center_assignments_by_account
      type  = "column"
      width = 6
    }

    chart {
      title = "Users with Access by Account"
      query = query.identity_center_users_by_account
      type  = "column"
      width = 6
    }

    chart {
      title = "Group Membership (Top 15)"
      query = query.identity_center_group_member_count
      type  = "bar"
      width = 6
    }

    chart {
      title = "Most Assigned Permission Sets (Top 15)"
      query = query.identity_center_permission_set_account_count
      type  = "bar"
      width = 6
    }

  }

  container {

    title = "Permissions by Account"

    table {
      title = "Account Assignments"
      query = query.identity_center_account_assignment_table
      width = 12
    }

    table {
      title = "Effective User Access (direct and via groups)"
      query = query.identity_center_user_access_table
      width = 12
    }

  }

  container {

    title = "Users and Groups"

    table {
      title = "Users"
      query = query.identity_center_user_table
      width = 6
    }

    table {
      title = "Groups"
      query = query.identity_center_group_table
      width = 6
    }

  }

  container {

    title = "Permission Sets"

    table {
      query = query.identity_center_permission_set_table
      width = 12
    }

  }

}

# Card Queries

query "identity_center_user_count" {
  sql = <<-EOQ
    ${local.identity_center_base_sql}
    select count(*) as "Users" from users;
  EOQ
}

query "identity_center_group_count" {
  sql = <<-EOQ
    ${local.identity_center_base_sql}
    select count(*) as "Groups" from groups;
  EOQ
}

query "identity_center_permission_set_count" {
  sql = <<-EOQ
    ${local.identity_center_base_sql}
    select count(*) as "Permission Sets" from permission_sets;
  EOQ
}

query "identity_center_account_assignment_count" {
  sql = <<-EOQ
    ${local.identity_center_base_sql}
    select count(*) as "Account Assignments" from assignments;
  EOQ
}

query "identity_center_users_without_access_count" {
  sql = <<-EOQ
    ${local.identity_center_base_sql},
    users_with_access as (
      select principal_id as user_id from assignments where principal_type = 'USER'
      union
      select m.member_id from assignments a join memberships m on a.principal_type = 'GROUP' and m.group_id = a.principal_id
    )
    select
      count(*) as value,
      'Users Without Account Access' as label,
      case count(*) when 0 then 'ok' else 'info' end as type
    from
      users u
    where
      u.id not in (select user_id from users_with_access);
  EOQ
}

query "identity_center_unassigned_permission_set_count" {
  sql = <<-EOQ
    ${local.identity_center_base_sql}
    select
      count(*) as value,
      'Unassigned Permission Sets' as label,
      case count(*) when 0 then 'ok' else 'alert' end as type
    from
      permission_sets ps
    where
      ps.arn not in (select permission_set_arn from assignments);
  EOQ
}

# Chart Queries

query "identity_center_assignments_by_account" {
  sql = <<-EOQ
    ${local.identity_center_base_sql}
    select
      account_name || ' (' || account_id || ')' as "Account",
      count(*) filter (where principal_type = 'USER') as "Users",
      count(*) filter (where principal_type = 'GROUP') as "Groups"
    from
      assignments
    group by
      account_name, account_id
    order by
      count(*) desc;
  EOQ
}

query "identity_center_users_by_account" {
  sql = <<-EOQ
    ${local.identity_center_base_sql},
    user_accounts as (
      select account_id, account_name, principal_id as user_id from assignments where principal_type = 'USER'
      union
      select a.account_id, a.account_name, m.member_id from assignments a join memberships m on a.principal_type = 'GROUP' and m.group_id = a.principal_id
    )
    select
      account_name || ' (' || account_id || ')' as "Account",
      count(distinct user_id) as "Users"
    from
      user_accounts
    group by
      account_name, account_id
    order by
      count(distinct user_id) desc;
  EOQ
}

query "identity_center_group_member_count" {
  sql = <<-EOQ
    ${local.identity_center_base_sql}
    select
      g.name as "Group",
      count(m.member_id) as "Members"
    from
      groups g
      left join memberships m on m.group_id = g.id
    group by
      g.name
    order by
      count(m.member_id) desc
    limit 15;
  EOQ
}

query "identity_center_permission_set_account_count" {
  sql = <<-EOQ
    ${local.identity_center_base_sql}
    select
      permission_set_name as "Permission Set",
      count(distinct account_id) as "Accounts"
    from
      assignments
    group by
      permission_set_name
    order by
      count(distinct account_id) desc
    limit 15;
  EOQ
}

# Table Queries

query "identity_center_account_assignment_table" {
  sql = <<-EOQ
    ${local.identity_center_base_sql},
    managed_policies as (
      select
        ps.arn as permission_set_arn,
        string_agg(mp.name, ', ' order by mp.name) as policies
      from
        permission_sets ps
        join aws_ssoadmin_managed_policy_attachment mp on mp.permission_set_arn = ps.arn
      group by
        ps.arn
    )
    select
      a.account_name as "Account",
      a.account_id as "Account ID",
      a.permission_set_name as "Permission Set",
      initcap(a.principal_type) as "Principal Type",
      coalesce(u.name, g.name, a.principal_id) as "Principal",
      case
        when a.principal_type = 'GROUP' then (select count(*) from memberships m where m.group_id = a.principal_id)
      end as "Group Members",
      mp.policies as "AWS Managed Policies"
    from
      assignments a
      left join users u on a.principal_type = 'USER' and u.id = a.principal_id
      left join groups g on a.principal_type = 'GROUP' and g.id = a.principal_id
      left join managed_policies mp on mp.permission_set_arn = a.permission_set_arn
    order by
      a.account_name, a.permission_set_name, a.principal_type, 5;
  EOQ
}

query "identity_center_user_access_table" {
  sql = <<-EOQ
    ${local.identity_center_base_sql},
    user_access as (
      select
        a.principal_id as user_id,
        a.account_id,
        a.account_name,
        a.permission_set_name,
        'Direct' as via
      from
        assignments a
      where
        a.principal_type = 'USER'
      union all
      select
        m.member_id,
        a.account_id,
        a.account_name,
        a.permission_set_name,
        'Group: ' || g.name
      from
        assignments a
        join groups g on g.id = a.principal_id
        join memberships m on m.group_id = a.principal_id
      where
        a.principal_type = 'GROUP'
    )
    select
      u.name as "User",
      u.display_name as "Display Name",
      ua.account_name as "Account",
      ua.account_id as "Account ID",
      ua.permission_set_name as "Permission Set",
      string_agg(ua.via, ', ' order by ua.via) as "Granted Via"
    from
      user_access ua
      join users u on u.id = ua.user_id
    group by
      u.name, u.display_name, ua.account_name, ua.account_id, ua.permission_set_name
    order by
      u.name, ua.account_name, ua.permission_set_name;
  EOQ
}

query "identity_center_user_table" {
  sql = <<-EOQ
    ${local.identity_center_base_sql}
    select
      u.name as "User",
      u.display_name as "Display Name",
      u.email as "Email",
      string_agg(g.name, ', ' order by g.name) as "Groups"
    from
      users u
      left join memberships m on m.member_id = u.id
      left join groups g on g.id = m.group_id
    group by
      u.id, u.name, u.display_name, u.email
    order by
      u.name;
  EOQ
}

query "identity_center_group_table" {
  sql = <<-EOQ
    ${local.identity_center_base_sql}
    select
      g.name as "Group",
      g.description as "Description",
      count(u.id) as "Members",
      string_agg(u.name, ', ' order by u.name) as "Users"
    from
      groups g
      left join memberships m on m.group_id = g.id
      left join users u on u.id = m.member_id
    group by
      g.id, g.name, g.description
    order by
      g.name;
  EOQ
}

query "identity_center_permission_set_table" {
  sql = <<-EOQ
    ${local.identity_center_base_sql},
    managed_policies as (
      select
        ps.arn as permission_set_arn,
        string_agg(mp.name, ', ' order by mp.name) as policies
      from
        permission_sets ps
        join aws_ssoadmin_managed_policy_attachment mp on mp.permission_set_arn = ps.arn
      group by
        ps.arn
    ),
    customer_policies as (
      select
        ps.arn as permission_set_arn,
        string_agg(cp.name, ', ' order by cp.name) as policies
      from
        permission_sets ps
        join aws_ssoadmin_customer_policy_attachment cp on cp.permission_set_arn = ps.arn
      group by
        ps.arn
    ),
    account_usage as (
      select
        permission_set_arn,
        count(*) as assignment_count,
        string_agg(distinct account_name, ', ') as accounts
      from
        assignments
      group by
        permission_set_arn
    )
    select
      ps.name as "Permission Set",
      ps.description as "Description",
      ps.session_duration as "Session Duration",
      mp.policies as "AWS Managed Policies",
      cp.policies as "Customer Managed Policies",
      ps.inline_policy is not null as "Inline Policy",
      coalesce(au.assignment_count, 0) as "Assignments",
      au.accounts as "Accounts",
      ps.arn as "ARN"
    from
      permission_sets ps
      left join managed_policies mp on mp.permission_set_arn = ps.arn
      left join customer_policies cp on cp.permission_set_arn = ps.arn
      left join account_usage au on au.permission_set_arn = ps.arn
    order by
      ps.name;
  EOQ
}
