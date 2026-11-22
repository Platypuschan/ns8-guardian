<template>
  <div class="page">
    <h1>{{ $t("members.title") }}</h1>
    <p>{{ $t("c.membersHelp") }}</p>
    <cv-inline-notification
      v-if="error"
      kind="error"
      :title="$t('c.error')"
      :sub-title="error"
      @close="error = ''"
    />
    <cv-inline-notification
      v-if="notHub"
      kind="info"
      :title="$t('c.hubOnly')"
    />
    <template v-else>
      <section class="add">
        <h2>{{ $t("c.addMember") }}</h2>
        <cv-text-input
          v-model="name"
          :label="$t('c.memberName')"
          :helper-text="$t('c.memberNameHelp')"
          :invalid-message="nameError"
          placeholder="ns8-office"
        />
        <cv-button
          type="button"
          :disabled="busy || !name.trim()"
          @click="add"
          >{{ $t("c.createToken") }}</cv-button
        >
        <div v-if="token" class="token">
          <cv-inline-notification
            kind="warning"
            :title="$t('c.tokenOnce')"
            :sub-title="$t('c.tokenOnceHelp')"
            :low-contrast="true"
          />
          <p>{{ $t("c.token") }}</p>
          <pre class="secret">{{ token }}</pre>
          <p>
            {{ $t("c.hubUrl") }}: <code>{{ hubUrl }}</code>
          </p>
        </div>
      </section>
      <section>
        <h2>{{ $t("c.connected") }} ({{ members.length }})</h2>
        <cv-button
          type="button"
          kind="ghost"
          size="small"
          :disabled="busy"
          @click="load"
          >{{ $t("c.refresh") }}</cv-button
        >
        <div class="table-scroll">
          <table class="bx--data-table">
            <thead>
              <tr>
                <th>{{ $t("c.name") }}</th>
                <th>{{ $t("c.address") }}</th>
                <th>{{ $t("c.lastAlert") }}</th>
                <th>{{ $t("c.lastHeartbeat") }}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="m in members" :key="m.name">
                <td>
                  {{ m.name }}
                  <span v-if="m.local">({{ $t("c.thisHub") }})</span>
                </td>
                <td>{{ m.ip_address || "—" }}</td>
                <td>{{ when(m.last_push) }}</td>
                <td>{{ when(m.last_heartbeat) }}</td>
                <td>
                  <cv-button
                    type="button"
                    v-if="!m.local"
                    kind="danger--ghost"
                    size="small"
                    :disabled="busy"
                    @click="remove(m.name)"
                    >{{ $t("c.remove") }}</cv-button
                  >
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </template>
  </div>
</template>
<script>
import task from "../task";
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
  }),
  beforeDestroy() {
    this.disposed = true;
    this.clearToken();
  },
  created() {
    this.load();
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
      if (!window.confirm(this.$t("c.confirmRemove", { name }))) return;
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
<style scoped>
.page {
  max-width: 1050px;
}
h1,
h2,
p,
section > * {
  margin-bottom: 1rem;
}
section {
  margin: 2rem 0;
}
pre {
  background: #f4f4f4;
  padding: 1rem;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.table-scroll {
  overflow-x: auto;
}
</style>
