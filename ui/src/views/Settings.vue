<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("settings.title") }}</h2>
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
    <cv-row v-if="success">
      <cv-column>
        <NsInlineNotification
          kind="success"
          :title="success"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <cv-row v-if="loading && !loaded">
      <cv-column>
        <cv-tile light>
          <cv-skeleton-text
            :paragraph="true"
            :line-count="6"
          ></cv-skeleton-text>
        </cv-tile>
      </cv-column>
    </cv-row>
    <cv-row v-if="loaded">
      <cv-column>
        <cv-tile light>
          <cv-form @submit.prevent>
            <p class="mg-bottom-md">{{ $t("c.intro") }}</p>
            <h4 class="mg-bottom-sm">{{ $t("c.role") }}</h4>
            <p class="mg-bottom-md">{{ $t("c.roleHelp") }}</p>
            <cv-radio-group vertical class="mg-bottom-md">
              <cv-radio-button
                v-model="form.role"
                name="role"
                value="hub"
                :label="$t('c.hub')"
                :disabled="configured || busy"
              />
              <cv-radio-button
                v-model="form.role"
                name="role"
                value="member"
                :label="$t('c.member')"
                :disabled="configured || busy"
              />
            </cv-radio-group>
            <div v-if="configured" class="bx--form__helper-text mg-bottom-lg">
              {{ $t("c.roleFixed") }}
            </div>
            <template v-if="form.role === 'hub'">
              <h4 class="mg-top-lg mg-bottom-md">{{ $t("c.hubSettings") }}</h4>
              <cv-text-input
                v-model="form.hub_host"
                :label="$t('c.hubHost')"
                placeholder="crowdsec.example.org"
                :helper-text="$t('c.hubHostHelp')"
                :invalid-message="fieldError('hub_host')"
                :disabled="busy"
                class="mg-bottom-md"
              />
              <NsToggle
                value="letsEncrypt"
                :label="$t('c.letsEncrypt')"
                v-model="form.lets_encrypt"
                :disabled="busy"
                class="mg-bottom-md"
              >
                <template #tooltip>{{ $t("c.letsEncryptHelp") }}</template>
                <template slot="text-left">{{ $t("c.disabled") }}</template>
                <template slot="text-right">{{ $t("c.enabled") }}</template>
              </NsToggle>
            </template>
            <template v-if="form.role === 'member'">
              <h4 class="mg-top-lg mg-bottom-md">
                {{ $t("c.memberSettings") }}
              </h4>
              <p v-if="config.hub_url" class="mg-bottom-md">
                {{ $t("c.connectedTo") }} <code>{{ config.hub_url }}</code>
                <span v-if="config.member_name">
                  ({{ $t("c.as") }} <code>{{ config.member_name }}</code
                  >)</span
                >
              </p>
              <cv-text-area
                v-model="form.token"
                :label="$t('c.token')"
                :helper-text="
                  configured ? $t('c.tokenKeep') : $t('c.tokenHelp')
                "
                :invalid-message="fieldError('token')"
                :rows="3"
                :disabled="busy"
                class="mg-bottom-sm"
              />
              <div class="bx--form__helper-text mg-bottom-md">
                {{ $t("c.tlsRequired") }}
              </div>
            </template>
            <template v-if="form.role">
              <h4 class="mg-top-lg mg-bottom-md">{{ $t("c.protection") }}</h4>
              <cv-text-input
                v-model="form.ban_duration"
                :label="$t('c.banDuration')"
                :helper-text="$t('c.banDurationHelp')"
                :invalid-message="fieldError('ban_duration')"
                :disabled="busy"
                class="mg-bottom-md"
              />
              <cv-text-area
                v-model="allowlist"
                :label="$t('c.allowlist')"
                :helper-text="$t('c.allowlistHelp')"
                :invalid-message="fieldError('allowlist')"
                :rows="4"
                :disabled="busy"
                placeholder="192.0.2.0/24&#10;2001:db8::/48"
                class="mg-bottom-md"
              />
              <NsToggle
                value="sambaAudit"
                :label="$t('c.sambaAudit')"
                v-model="form.samba_audit"
                :disabled="busy"
                class="mg-bottom-md"
              >
                <template #tooltip>{{ $t("c.sambaAuditHelp") }}</template>
                <template slot="text-left">{{ $t("c.disabled") }}</template>
                <template slot="text-right">{{ $t("c.enabled") }}</template>
              </NsToggle>
              <NsToggle
                value="communityBlocklist"
                :label="$t('c.communityBlocklist')"
                v-model="form.community_blocklist"
                :disabled="busy"
                class="mg-bottom-sm"
              >
                <template slot="text-left">{{ $t("c.disabled") }}</template>
                <template slot="text-right">{{ $t("c.enabled") }}</template>
              </NsToggle>
              <div class="bx--form__helper-text mg-bottom-md">
                {{ $t("c.communityBlocklistHelp") }}
              </div>
              <template v-if="form.community_blocklist">
                <NsToggle
                  value="communitySharing"
                  :label="$t('c.communitySharing')"
                  v-model="form.community_sharing"
                  :disabled="busy"
                  class="mg-bottom-sm"
                >
                  <template slot="text-left">{{ $t("c.disabled") }}</template>
                  <template slot="text-right">{{ $t("c.enabled") }}</template>
                </NsToggle>
                <div class="bx--form__helper-text mg-bottom-md">
                  {{ $t("c.communitySharingHelp") }}
                </div>
              </template>
            </template>
            <NsButton
              type="button"
              kind="primary"
              :icon="Save20"
              :loading="busy"
              :disabled="busy || !form.role"
              class="mg-top-md"
              @click="save"
              >{{ $t("c.save") }}</NsButton
            >
          </cv-form>
        </cv-tile>
      </cv-column>
    </cv-row>
  </cv-grid>
</template>
<script>
import task from "../task";
import Save20 from "@carbon/icons-vue/es/save/20";
export default {
  name: "Settings",
  mixins: [task],
  data: () => ({
    loading: true,
    loaded: false,
    busy: false,
    error: "",
    success: "",
    errors: {},
    config: {},
    allowlist: "",
    Save20,
    form: {
      role: "",
      hub_host: "",
      lets_encrypt: true,
      token: "",
      ban_duration: "4h",
      samba_audit: true,
      community_blocklist: false,
      community_sharing: false,
    },
  }),
  computed: {
    configured() {
      return !!this.config.role;
    },
  },
  created() {
    this.load();
  },
  beforeDestroy() {
    this.form.token = "";
  },
  methods: {
    fieldError(field) {
      return this.errors[field] ? this.$t("c.err." + this.errors[field]) : "";
    },
    async load() {
      this.form.token = "";
      this.loading = true;
      try {
        this.config = await this.task("get-configuration");
        Object.keys(this.form).forEach((key) => {
          if (key !== "token" && key in this.config)
            this.form[key] = this.config[key];
        });
        this.form.token = "";
        this.allowlist = (this.config.allowlist || []).join("\n");
        this.loaded = true;
      } catch (e) {
        this.error = e.message;
      } finally {
        this.loading = false;
      }
    },
    async save() {
      this.busy = true;
      this.error = "";
      this.success = "";
      this.errors = {};
      const data = {
        role: this.form.role,
        ban_duration: this.form.ban_duration.trim(),
        samba_audit: this.form.samba_audit,
        community_blocklist: this.form.community_blocklist,
        community_sharing:
          this.form.community_blocklist && this.form.community_sharing,
        allowlist: this.allowlist
          .split(/[\s,]+/)
          .map((v) => v.trim())
          .filter((v) => v),
      };
      if (this.form.role === "hub") {
        data.hub_host = this.form.hub_host.trim();
        data.lets_encrypt = this.form.lets_encrypt;
      } else {
        if (this.form.token.trim()) data.token = this.form.token.trim();
      }
      try {
        await this.task("configure-module", data);
        this.success = this.$t("c.saved");
        await this.load();
      } catch (e) {
        this.parseValidation(e);
      } finally {
        this.busy = false;
      }
    },
    parseValidation(e) {
      if (e.validation && e.validation.length) {
        e.validation.forEach((v) =>
          this.$set(this.errors, v.field || v.parameter, v.error)
        );
        return;
      }
      this.error = e.message;
    },
  },
};
</script>
