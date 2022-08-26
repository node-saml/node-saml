module.exports = {
  dataSource: "prs",
  prefix: "",
  onlyMilestones: false,
  ignoreTagsWith: ["v2.2.0", "v2.1.0", "v2.0.6", "v2.0.5", "v2.0.4", "v2.0.3", "v2.0.2", "v2.0.1", "v2.0.0", "v1.5.0", "v1.4.2", "v1.4.1", "v1.4.0", "v1.3.5", "v1.3.4", "v1.3.3", "v1.3.2", "v1.3.1", "v1.3.0", "v1.2.0", "v1.1.0", "v1.0.0", "v0.35.0", "v0.34.0", "v0.33.0", "v0.32.1", "v0.32.0", "v0.31.0", "v0.30.0", "v0.20.2", "v0.20.1", "v0.20.0", "v0.16.2", "v0.16.1", "v0.16.0", "v0.15.0", "v0.14.0", "v0.13.0", "v0.12.0", "v0.11.1", "v0.11.0", "v0.10.0", "v0.9.2", "v0.9.1", "v0.9.0", "v0.8.0", "v0.7.0", "v0.6.2", "v0.6.1", "v0.6.0", "v0.5.3", "v0.5.2", "v0.5.1", "v0.5.0", "v0.4.0", "v0.3.0", "v0.2.1", "v0.2.0", "v0.1.0", "0.0.3"],  ignoreLabels: [
    "semver-major",
    "semver-minor",
    "semver-patch",
    "closed",
    "breaking-change",
    "bug",
    "enhancement",
    "dependencies",
    "documentation",
    "chore",
    "new-feature",
  ],
  tags: "all",
  groupBy: {
    "Major Changes": ["semver-major", "breaking-change"],
    "Minor Changes": ["semver-minor", "enhancement", "new-feature"],
    Dependencies: ["dependencies"],
    "Bug Fixes": ["semver-patch", "bug", "security"],
    Documentation: ["documentation"],
    "Technical Tasks": ["chore"],
    Other: ["..."],
  },
  changelogFilename: "CHANGELOG.md",
  username: "node-saml",
  repo: "node-saml",
  template: {
    issue: function (placeholders) {
      const parts = [
        "-",
        placeholders.labels,
        placeholders.name,
        `[${placeholders.text}](${placeholders.url})`,
      ];
      return parts.filter((_) => _).join(" ");
    },
    release: function (placeholders) {
      let dateParts = placeholders.date.split("/");
      let placeholdersDate = new Date(
        Number(dateParts[2]),
        Number(dateParts[1]) - 1,
        Number(dateParts[0])
      );
      let isoDateString = placeholdersDate.toISOString().split("T")[0];
      placeholders.body = placeholders.body.replace(
        "*No changelog for this release.*",
        "\n_No changelog for this release._"
      );
      return `## ${placeholders.release} (${isoDateString})\n${placeholders.body}`;
    },
    group: function (placeholders) {
      const iconMap = {
        Enhancements: "🚀",
        "Minor Changes": "🚀",
        "Bug Fixes": "🐛",
        Documentation: "📚",
        "Technical Tasks": "⚙️",
        "Major Changes": "💣",
        Dependencies: "🔗",
      };
      const icon = iconMap[placeholders.heading] || "🙈";
      return "\n#### " + icon + " " + placeholders.heading + ":\n";
    },
  },
};
