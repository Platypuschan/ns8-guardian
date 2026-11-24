<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("members.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column>
        <p class="mg-bottom-md">{{ $t("c.membersHelp") }}</p>
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
    <cv-row v-if="notHub">
      <cv-column>
        <NsInlineNotification
          kind="info"
          :title="$t('c.hubOnly')"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <template v-else>
      <cv-row>
        <cv-column class="page-subtitle">
          <h4>{{ $t("c.addMember") }}</h4>
        </cv-column>
      </cv-row>
      <cv-row>
        <cv-column>
          <cv-tile light>
            <cv-form @submit.prevent>
              <cv-text-input
                v-model="name"
                :label="$t('c.memberName')"
                :helper-text="$t('c.memberNameHelp')"
                :invalid-message="nameError"
                :disabled="busy"
                placeholder="ns8-office"
                class="mg-bottom-md"
              />
              <NsButton
                type="button"
                kind="primary"
                :icon="Add20"
                :loading="busy"
                :disabled="busy || !name.trim()"
                @click="add"
                >{{ $t("c.createToken") }}</NsButton
              >
            </cv-form>
            <div v-if="token" class="token mg-top-lg">
              <NsInlineNotification
                kind="warning"
                :title="$t('c.tokenOnce')"
                :description="$t('c.tokenOnceHelp')"
                :showCloseButton="false"
              />
              <div class="bx--form__helper-text mg-bottom-sm">
                {{ $t("c.token") }}
              </div>
              <cv-code-snippet kind="multi" class="secret mg-bottom-md">{{
                token
              }}</cv-code-snippet>
              <p>
                {{ $t("c.hubUrl") }}: <code>{{ hubUrl }}</code>
              </p>
            </div>
          </cv-tile>
        </cv-column>
      </cv-row>
      <cv-row>
        <cv-column class="page-subtitle">
          <h4>{{ $t("c.connected") }} ({{ members.length }})</h4>
        </cv-column>
      </cv-row>
      <cv-row class="toolbar">
        <cv-column>
          <NsButton
            type="button"
            kind="ghost"
            :icon="Renew20"
            :disabled="busy"
            @click="load"
            >{{ $t("c.refresh") }}</NsButton
          >
        </cv-column>
      </cv-row>
      <cv-row>
        <cv-column>
          <cv-tile v-if="!members.length && !busy" light>
            <NsEmptyState :title="$t('c.noMembers')" />
          </cv-tile>
          <cv-data-table v-else :columns="columns" :zebra="false">
            <template slot="data">
              <cv-data-table-row
                v-for="m in members"
                :key="m.name"
                :value="m.name"
              >
                <cv-data-table-cell>
                  {{ m.name }}
                  <span v-if="m.local">({{ $t("c.thisHub") }})</span>
                </cv-data-table-cell>
                <cv-data-table-cell>{{
                  m.ip_address || "—"
                }}</cv-data-table-cell>
                <cv-data-table-cell>{{ when(m.last_push) }}</cv-data-table-cell>
                <cv-data-table-cell>{{
                  when(m.last_heartbeat)
                }}</cv-data-table-cell>
                <cv-data-table-cell>
                  <NsButton
                    v-if="!m.local"
                    type="button"
                    kind="danger--ghost"
                    size="small"
                    :icon="TrashCan20"
                    :disabled="busy"
                    @click="toRemove = m.name"
                    >{{ $t("c.remove") }}</NsButton
                  >
                </cv-data-table-cell>
              </cv-data-table-row>
            </template>
          </cv-data-table>
        </cv-column>
      </cv-row>
      <NsDangerDeleteModal
        :isShown="!!toRemove"
        :name="toRemove"
        :title="$t('c.removeTitle')"
        :warning="$t('c.removeWarning')"
        :description="$t('c.confirmRemove', { name: toRemove })"
        :typeToConfirm="$t('c.typeToConfirm', { name: toRemove })"
        :cancelLabel="$t('c.cancel')"
        :deleteLabel="$t('c.removeConfirm')"
        @hide="toRemove = ''"
        @confirmDelete="remove(toRemove)"
      />
    </template>
  </cv-grid>
</template>
<script>
import task from "../task";
import Add20 from "@carbon/icons-vue/es/add/20";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import TrashCan20 from "@carbon/icons-vue/es/trash-can/20";
export default {
  name: "Members",
  mixins: [task],
  data: () => ({
    disposed: false,
    busy: false,
    error: "",
    notHub: false,
    members: [],
    name: "",
    nameError: "",
    token: "",
    hubUrl: "",
    toRemove: "",
    Add20,
    Renew20,
    TrashCan20,
  }),
  beforeDestroy() {
    this.disposed = true;
    this.clearToken();
  },
  created() {
    this.load();
  },
  computed: {
    columns() {
      return [
        this.$t("c.name"),
        this.$t("c.address"),
        this.$t("c.lastAlert"),
        this.$t("c.lastHeartbeat"),
        "",
      ];
    },
  },
  methods: {
    clearToken() {
      this.token = "";
      this.hubUrl = "";
    },
    when(value) {
      if (!value || String(value).startsWith("0001")) return "—";
      // The backend reports Unix seconds; ISO strings are accepted as well.
      const date = new Date(typeof value === "number" ? value * 1000 : value);
      return Number.isNaN(date.getTime())
        ? String(value)
        : date.toLocaleString();
    },
    async load() {
      this.clearToken();
      this.error = "";
      this.busy = true;
      try {
        const config = await this.task("get-configuration");
        this.notHub = config.role !== "hub";
        if (!this.notHub) {
          this.members = (await this.task("list-members")).members || [];
        }
      } catch (e) {
        this.error = e.message;
      } finally {
        this.busy = false;
      }
    },
    async add() {
      this.busy = true;
      this.nameError = "";
      this.clearToken();
      this.error = "";
      try {
        const result = await this.task("add-member", {
          name: this.name.trim(),
        });
        if (this.disposed) return;
        this.token = result.token;
        this.hubUrl = result.hub_url || "";
        this.name = "";
        this.members = (await this.task("list-members")).members || [];
      } catch (e) {
        if (e.validation && e.validation.length) {
          this.nameError = this.$t("c.err." + e.validation[0].error);
        } else {
          this.error = e.message;
        }
      } finally {
        this.busy = false;
      }
    },
    async remove(name) {
      this.clearToken();
      this.toRemove = "";
      this.busy = true;
      try {
        await this.task("remove-member", { name });
        this.members = (await this.task("list-members")).members || [];
      } catch (e) {
        this.error = e.message;
      } finally {
        this.busy = false;
      }
    },
  },
};
</script>
