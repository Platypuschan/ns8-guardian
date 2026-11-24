<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("status.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row v-if="error">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('c.error')"
          :description="error"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <cv-row class="toolbar">
      <cv-column>
        <NsButton
          type="button"
          kind="ghost"
          :icon="Renew20"
          :disabled="loading"
          @click="refresh"
          >{{ $t("c.refresh") }}</NsButton
        >
      </cv-column>
    </cv-row>
    <cv-row v-if="loading && !status">
      <cv-column>
        <cv-tile light>
          <cv-skeleton-text
            :paragraph="true"
            :line-count="4"
          ></cv-skeleton-text>
        </cv-tile>
      </cv-column>
    </cv-row>
    <template v-if="status">
      <cv-row v-if="!status.role">
        <cv-column>
          <NsInlineNotification
            kind="info"
            :title="$t('c.notConfigured')"
            :showCloseButton="false"
          />
        </cv-column>
      </cv-row>
      <template v-else>
        <cv-row>
          <cv-column :md="4" :max="4">
            <NsInfoCard
              light
              :title="roleShort"
              :description="$t('c.role')"
              :icon="Security32"
              :loading="loading"
              class="min-height-card"
            />
          </cv-column>
          <cv-column :md="4" :max="4">
            <NsInfoCard
              light
              :title="syncShort"
              :description="$t('c.centralSync')"
              :icon="Network_332"
              :loading="loading"
              class="min-height-card"
            />
          </cv-column>
          <cv-column :md="4" :max="4">
            <NsInfoCard
              light
              :title="display(status.active_bans)"
              :description="$t('c.activeBans')"
              :icon="Locked32"
              :loading="loading"
              class="min-height-card"
            />
          </cv-column>
          <cv-column
            v-if="status.community && status.community.enabled"
            :md="4"
            :max="4"
          >
            <NsInfoCard
              light
              :title="display(status.community.entries)"
              :description="$t('c.activeCommunity')"
              :icon="Cloud32"
              :loading="loading"
              class="min-height-card"
            />
          </cv-column>
          <cv-column v-if="status.role === 'hub'" :md="4" :max="4">
            <NsInfoCard
              light
              :title="display(status.members)"
              :description="$t('c.membersCount')"
              :icon="UserMultiple32"
              :loading="loading"
              class="min-height-card"
            />
          </cv-column>
        </cv-row>
        <cv-row v-if="status.community && status.community.error">
          <cv-column>
            <NsInlineNotification
              kind="warning"
              :title="$t('c.communityError')"
              :description="status.community.error"
              :showCloseButton="false"
            />
          </cv-column>
        </cv-row>
        <cv-row>
          <cv-column class="page-subtitle">
            <h4>{{ $t("c.services") }}</h4>
          </cv-column>
        </cv-row>
        <cv-row>
          <cv-column
            v-for="service in serviceList"
            :key="service.name"
            :md="4"
            :max="4"
          >
            <NsSystemdServiceCard
              light
              class="min-height-card"
              :serviceName="service.name"
              :active="service.active"
              :failed="service.failed"
              :enabled="true"
              :activeLabel="$t('c.svcActive')"
              :inactiveLabel="$t('c.svcInactive')"
              :failedLabel="$t('c.svcFailed')"
              :enabledLabel="$t('c.svcEnabled')"
              :disaledLabel="$t('c.svcDisabled')"
              :icon="Security32"
            />
          </cv-column>
        </cv-row>
        <cv-row>
          <cv-column class="page-subtitle">
            <h4>{{ $t("c.details") }}</h4>
          </cv-column>
        </cv-row>
        <cv-row>
          <cv-column>
            <cv-tile light>
              <cv-structured-list>
                <template slot="items">
                  <cv-structured-list-item>
                    <cv-structured-list-data>{{
                      $t("c.hubUrl")
                    }}</cv-structured-list-data>
                    <cv-structured-list-data>
                      <code>{{ display(status.hub_url) }}</code>
                    </cv-structured-list-data>
                  </cv-structured-list-item>
                  <cv-structured-list-item>
                    <cv-structured-list-data>{{
                      $t("c.apiConnection")
                    }}</cv-structured-list-data>
                    <cv-structured-list-data>{{
                      status.lapi === "ok"
                        ? $t("c.ready")
                        : display(status.lapi)
                    }}</cv-structured-list-data>
                  </cv-structured-list-item>
                  <cv-structured-list-item>
                    <cv-structured-list-data>{{
                      $t("c.centralSync")
                    }}</cv-structured-list-data>
                    <cv-structured-list-data>{{
                      syncState
                    }}</cv-structured-list-data>
                  </cv-structured-list-item>
                  <cv-structured-list-item>
                    <cv-structured-list-data>{{
                      $t("c.pendingChanges")
                    }}</cv-structured-list-data>
                    <cv-structured-list-data>{{
                      display(status.sync && status.sync.pending)
                    }}</cv-structured-list-data>
                  </cv-structured-list-item>
                  <cv-structured-list-item>
                    <cv-structured-list-data>{{
                      $t("c.lastSuccess")
                    }}</cv-structured-list-data>
                    <cv-structured-list-data>{{
                      moment(status.sync && status.sync.last_success)
                    }}</cv-structured-list-data>
                  </cv-structured-list-item>
                  <cv-structured-list-item>
                    <cv-structured-list-data>{{
                      $t("c.syncAge")
                    }}</cv-structured-list-data>
                    <cv-structured-list-data>{{
                      display(status.sync && status.sync.age_seconds)
                    }}</cv-structured-list-data>
                  </cv-structured-list-item>
                  <cv-structured-list-item>
                    <cv-structured-list-data>{{
                      $t("c.eventIngress")
                    }}</cv-structured-list-data>
                    <cv-structured-list-data>
                      <code>{{
                        display(
                          status.event_ingress && status.event_ingress.endpoint
                        )
                      }}</code>
                    </cv-structured-list-data>
                  </cv-structured-list-item>
                  <cv-structured-list-item>
                    <cv-structured-list-data>{{
                      $t("c.pendingEvents")
                    }}</cv-structured-list-data>
                    <cv-structured-list-data>{{
                      display(
                        status.event_ingress && status.event_ingress.pending
                      )
                    }}</cv-structured-list-data>
                  </cv-structured-list-item>
                  <cv-structured-list-item>
                    <cv-structured-list-data>{{
                      $t("c.unackedEvents")
                    }}</cv-structured-list-data>
                    <cv-structured-list-data>
                      {{ display(status.sync && status.sync.event_unacked) }}
                      <span v-if="ackState !== $t('c.unknown')"
                        >({{ $t(ackState) }})</span
                      >
                    </cv-structured-list-data>
                  </cv-structured-list-item>
                  <cv-structured-list-item>
                    <cv-structured-list-data>{{
                      $t("c.replayedEvents")
                    }}</cv-structured-list-data>
                    <cv-structured-list-data>{{
                      display(status.sync && status.sync.event_replayed_total)
                    }}</cv-structured-list-data>
                  </cv-structured-list-item>
                  <cv-structured-list-item>
                    <cv-structured-list-data>{{
                      $t("c.sources")
                    }}</cv-structured-list-data>
                    <cv-structured-list-data>
                      <div>SSH</div>
                      <div
                        v-for="(modules, kind) in status.sources"
                        :key="kind"
                      >
                        {{ $t("c.kind." + kind) }}: {{ modules.join(", ") }}
                      </div>
                    </cv-structured-list-data>
                  </cv-structured-list-item>
                </template>
              </cv-structured-list>
            </cv-tile>
          </cv-column>
        </cv-row>
      </template>
    </template>
  </cv-grid>
</template>
<script>
import task from "../task";
import Security32 from "@carbon/icons-vue/es/security/32";
import Locked32 from "@carbon/icons-vue/es/locked/32";
import Cloud32 from "@carbon/icons-vue/es/cloud/32";
import Network_332 from "@carbon/icons-vue/es/network--3/32";
import UserMultiple32 from "@carbon/icons-vue/es/user--multiple/32";
import Renew20 from "@carbon/icons-vue/es/renew/20";
export default {
  name: "Status",
  mixins: [task],
  data: () => ({
    loading: false,
    error: "",
    status: null,
    Security32,
    Locked32,
    Cloud32,
    Network_332,
    UserMultiple32,
    Renew20,
  }),
  computed: {
    roleShort() {
      return this.status && this.status.role === "hub"
        ? this.$t("c.roleHubShort")
        : this.$t("c.roleMemberShort");
    },
    serviceList() {
      const services = (this.status && this.status.services) || {};
      const rank = (name) => {
        const i = [
          ".service",
          "-bouncer.",
          "-sync.",
          "-gateway.",
          "-refresh.",
        ].findIndex(
          (part) =>
            name.includes(part) && (part !== ".service" || !/-\w+\./.test(name))
        );
        return i < 0 ? 99 : i;
      };
      return Object.keys(services)
        .sort((a, b) => rank(a) - rank(b) || a.localeCompare(b))
        .map((name) => ({
          name,
          active: services[name] === "active",
          failed: services[name] === "failed",
        }));
    },
    ackState() {
      const sync = this.status && this.status.sync;
      if (!sync || typeof sync.event_unacked !== "number") return "c.unknown";
      return sync.event_unacked > 0 ? "c.ackWaiting" : "c.ackIdle";
    },
    syncKind() {
      const sync = this.status && this.status.sync;
      if (!sync) return "unknown";
      if (sync.error) return "error";
      if (
        sync.import_overload === true ||
        sync.local_export_overload === true ||
        (typeof sync.quota_pending === "number" && sync.quota_pending > 0)
      ) {
        return "overload";
      }
      if (
        sync.stale === true ||
        (typeof sync.age_seconds === "number" && sync.age_seconds > 60)
      ) {
        return "stale";
      }
      if (sync.pending) return "pending";
      if ((sync.pending === 0 || sync.pending === false) && sync.last_success) {
        return "idle";
      }
      return "unknown";
    },
    syncState() {
      const kind = this.syncKind;
      if (kind === "error") return String(this.status.sync.error);
      const text = {
        overload: "c.syncOverload",
        stale: "c.syncStale",
        pending: "c.pending",
        idle: "c.syncIdle",
        unknown: "c.unknown",
      };
      return this.$t(text[kind]);
    },
    // short form for the status card; the long text stays in the details list
    syncShort() {
      const text = {
        error: "c.syncShortError",
        overload: "c.syncShortOverload",
        stale: "c.syncShortStale",
        pending: "c.syncShortPending",
        idle: "c.syncShortIdle",
        unknown: "c.unknown",
      };
      return this.$t(text[this.syncKind]);
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
