<template>
  <div class="page">
    <h1>{{ $t("eventSources.title") }}</h1>
    <p>{{ $t("c.eventSourcesHelp") }}</p>
    <cv-inline-notification
      v-if="error"
      kind="error"
      :title="$t('c.error')"
      :sub-title="error"
      @close="error = ''"
    />
    <section>
      <h2>{{ $t("c.addEventSource") }}</h2>
      <cv-text-input
        v-model="name"
        :label="$t('c.name')"
        :helper-text="$t('c.memberNameHelp')"
        :invalid-message="fieldError('name')"
      />
      <cv-text-input
        v-model="module"
        :label="$t('c.moduleIdentity')"
        :helper-text="$t('c.moduleIdentityHelp')"
        :invalid-message="fieldError('module')"
        placeholder="gitea1"
      />
      <cv-button
        type="button"
        :disabled="busy || !name.trim() || !module.trim()"
        @click="add"
        >{{ $t("c.createToken") }}</cv-button
      >
      <div v-if="token" class="token">
        <cv-inline-notification
          kind="warning"
          :title="$t('c.tokenOnce')"
          :sub-title="$t('c.sourceTokenOnce')"
        />
        <p>{{ $t("c.sourceToken") }}</p>
        <pre class="secret">{{ token }}</pre>
        <p>
          {{ $t("c.eventIngress") }}: <code>{{ endpoint }}</code>
        </p>
        <p>{{ $t("c.sourceTokenScope") }}</p>
      </div>
    </section>
    <section>
      <h2>{{ $t("c.registeredSources") }} ({{ sources.length }})</h2>
      <cv-button type="button" kind="ghost" :disabled="busy" @click="load">{{
        $t("c.refresh")
      }}</cv-button>
      <div class="table-scroll">
        <table class="bx--data-table">
          <thead>
            <tr>
              <th>{{ $t("c.name") }}</th>
              <th>{{ $t("c.moduleIdentity") }}</th>
              <th>{{ $t("c.sourceType") }}</th>
              <th>{{ $t("c.sourceStatus") }}</th>
              <th>{{ $t("c.actions") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="source in sources" :key="source.name">
              <td>{{ source.name }}</td>
              <td>{{ source.module }}</td>
              <td>{{ $t("c.authEvents") }}</td>
              <td>
                {{ sourceState(source) }}
                <p v-if="source.active === 0">
                  {{ $t("c.sourcePendingRecovery") }}
                </p>
              </td>
              <td>
                <cv-button
                  type="button"
                  kind="danger--ghost"
                  size="small"
                  :disabled="busy"
                  @click="remove(source.name)"
                  >{{ $t("c.remove") }}</cv-button
                >
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="!sources.length && !busy">{{ $t("c.noEventSources") }}</p>
    </section>
    <section>
      <h2>{{ $t("c.integrationGuide") }}</h2>
      <p>{{ $t("c.hookGuide") }}</p>
      <p>{{ $t("c.adapterGuide") }}</p>
      <p>{{ $t("c.fallbackGuide") }}</p>
    </section>
  </div>
</template>
<script>
import task from "../task";
export default {
  name: "EventSources",
  mixins: [task],
  data: () => ({
    disposed: false,
    busy: false,
    error: "",
    errors: {},
    name: "",
    module: "",
    sources: [],
    token: "",
    endpoint: "",
  }),
  created() {
    this.load();
  },
  beforeDestroy() {
    this.disposed = true;
    this.clearToken();
  },
  methods: {
    sourceState(source) {
      if (source.active === 0) return this.$t("c.sourcePending");
      if (source.active === 1) return this.$t("c.sourceActive");
      return this.$t("c.unknown");
    },
    clearToken() {
      this.token = "";
      this.endpoint = "";
    },
    fieldError(field) {
      return this.errors[field] || "";
    },
    async load() {
      this.clearToken();
      this.error = "";
      this.busy = true;
      try {
        this.sources = (await this.task("list-event-sources")).sources || [];
      } catch (e) {
        this.error = e.message;
      } finally {
        this.busy = false;
      }
    },
    async add() {
      this.clearToken();
      this.error = "";
      this.errors = {};
      this.busy = true;
      try {
        const result = await this.task("add-event-source", {
          name: this.name.trim(),
          module: this.module.trim(),
        });
        if (this.disposed) return;
        this.token = result.token;
        this.endpoint = result.endpoint || "";
        this.name = "";
        this.module = "";
        this.sources = (await this.task("list-event-sources")).sources || [];
      } catch (e) {
        if (e.validation && e.validation.length) {
          e.validation.forEach((v) =>
            this.$set(
              this.errors,
              v.field || v.parameter,
              this.$t("c.err." + v.error)
            )
          );
        } else {
          this.error = e.message;
        }
      } finally {
        this.busy = false;
      }
    },
    async remove(name) {
      this.clearToken();
      if (!window.confirm(this.$t("c.confirmRemoveSource", { name }))) return;
      this.error = "";
      this.busy = true;
      try {
        await this.task("remove-event-source", { name });
        this.sources = (await this.task("list-event-sources")).sources || [];
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
.secret {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: #f4f4f4;
  padding: 1rem;
}
.table-scroll {
  overflow-x: auto;
}
</style>
