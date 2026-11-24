<template>
  <div class="page">
    <h1>{{ $t("status.title") }}</h1>
    <cv-button type="button" :disabled="loading" @click="refresh">{{
      $t("c.refresh")
    }}</cv-button>
    <cv-inline-notification
      v-if="error"
      kind="error"
      :title="$t('c.error')"
      :sub-title="error"
    />
    <template v-if="status">
      <p v-if="!status.role">{{ $t("c.notConfigured") }}</p>
      <dl v-else>
        <dt>{{ $t("c.role") }}</dt>
        <dd>{{ status.role === "hub" ? $t("c.hub") : $t("c.member") }}</dd>
        <dt>{{ $t("c.hubUrl") }}</dt>
        <dd>
          <code>{{ status.hub_url }}</code>
        </dd>
        <dt>{{ $t("c.apiConnection") }}</dt>
        <dd>
          {{ status.lapi === "ok" ? $t("c.ready") : display(status.lapi) }}
        </dd>
        <dt>{{ $t("c.activeBans") }}</dt>
        <dd>{{ display(status.active_bans) }}</dd>
        <template v-if="status.community && status.community.enabled">
          <dt>{{ $t("c.activeCommunity") }}</dt>
          <dd>{{ display(status.community.entries) }}</dd>
          <template v-if="status.community.error">
            <dt>{{ $t("c.communityError") }}</dt>
            <dd>{{ status.community.error }}</dd>
          </template>
        </template>
        <template v-if="status.role === 'hub'">
          <dt>{{ $t("c.membersCount") }}</dt>
          <dd>{{ display(status.members) }}</dd>
        </template>
        <dt>{{ $t("c.centralSync") }}</dt>
        <dd>{{ syncState }}</dd>
        <dt>{{ $t("c.pendingChanges") }}</dt>
        <dd>{{ display(status.sync && status.sync.pending) }}</dd>
        <dt>{{ $t("c.lastSuccess") }}</dt>
        <dd>{{ moment(status.sync && status.sync.last_success) }}</dd>
        <dt>{{ $t("c.syncAge") }}</dt>
        <dd>{{ display(status.sync && status.sync.age_seconds) }}</dd>
        <dt>{{ $t("c.eventIngress") }}</dt>
        <dd>
          <code>{{
            display(status.event_ingress && status.event_ingress.endpoint)
          }}</code>
        </dd>
        <dt>{{ $t("c.pendingEvents") }}</dt>
        <dd>
          {{ display(status.event_ingress && status.event_ingress.pending) }}
        </dd>
        <dt>{{ $t("c.unackedEvents") }}</dt>
        <dd>
          {{ display(status.sync && status.sync.event_unacked) }}
          <span v-if="ackState !== $t('c.unknown')">({{ $t(ackState) }})</span>
        </dd>
        <dt>{{ $t("c.replayedEvents") }}</dt>
        <dd>{{ display(status.sync && status.sync.event_replayed_total) }}</dd>
        <dt>{{ $t("c.sources") }}</dt>
        <dd>
          <ul>
            <li>SSH</li>
            <li v-for="(modules, kind) in status.sources" :key="kind">
              {{ $t("c.kind." + kind) }}: {{ modules.join(", ") }}
            </li>
          </ul>
        </dd>
        <dt>{{ $t("c.services") }}</dt>
        <dd>
          <ul>
            <li v-for="(state, name) in status.services" :key="name">
              {{ name }}: {{ state }}
            </li>
          </ul>
        </dd>
      </dl>
    </template>
  </div>
</template>
<script>
import task from "../task";
export default {
  name: "Status",
  mixins: [task],
  data: () => ({ loading: false, error: "", status: null }),
  computed: {
    ackState() {
      const sync = this.status && this.status.sync;
      if (!sync || typeof sync.event_unacked !== "number") return "c.unknown";
      return sync.event_unacked > 0 ? "c.ackWaiting" : "c.ackIdle";
    },
    syncState() {
      const sync = this.status && this.status.sync;
      if (!sync) return this.$t("c.unknown");
      if (sync.error) return String(sync.error);
      if (
        sync.import_overload === true ||
        sync.local_export_overload === true ||
        (typeof sync.quota_pending === "number" && sync.quota_pending > 0)
      ) {
        return this.$t("c.syncOverload");
      }
      if (
        sync.stale === true ||
        (typeof sync.age_seconds === "number" && sync.age_seconds > 60)
      ) {
        return this.$t("c.syncStale");
      }
      if (sync.pending) return this.$t("c.pending");
      if ((sync.pending === 0 || sync.pending === false) && sync.last_success) {
        return this.$t("c.syncIdle");
      }
      return this.$t("c.unknown");
    },
  },
  created() {
    this.refresh();
  },
  methods: {
    display(value) {
      return value === undefined || value === null || value === ""
        ? this.$t("c.unknown")
        : String(value);
    },
    moment(value) {
      // Unix seconds from the backend (sync.last_success).
      return typeof value === "number" && value > 0
        ? new Date(value * 1000).toLocaleString()
        : this.display(value);
    },
    async refresh() {
      this.loading = true;
      this.error = "";
      try {
        this.status = await this.task("get-companion-status");
      } catch (e) {
        this.error = e.message;
      } finally {
        this.loading = false;
      }
    },
  },
};
</script>
<style scoped>
.page {
  max-width: 1050px;
}
h1 {
  margin-bottom: 1rem;
}
dl {
  margin: 2rem 0;
  display: grid;
  grid-template-columns: 14rem 1fr;
  gap: 0.6rem;
}
</style>
